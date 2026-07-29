"""Validation boundary and subprocess runner for a single job."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
import fcntl
import json
import os
import pwd
import queue
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .clonezilla import Command, build_command
from .domain import DeviceIdentity, JobOperation, PublicJobSpec
from .draft import image_fingerprint
from .inventory import BlockDevice, scan_block_devices
from .protocol import PROTOCOL_VERSION, read_message, redact_text, write_message
from .progress import ProgressParser
from .preflight import PreflightService
from .storage import PrivilegedStorage, StorageRequest
from .image_explorer import ExplorerRequest, ImageExplorer
from .images import ImageStatus, parse_clonezilla_image


class RunnerValidationError(ValueError):
    def __init__(self, message: str, code: str = "validation-failed") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RunResult:
    argv: tuple[str, ...]
    returncode: int | None
    dry_run: bool
    stdout: str = ""
    stderr: str = ""
    cancelled: bool = False
    cleanup: str = "not-needed"


LOCK_PATH = Path("/run/transume/job.lock")
RUNTIME_DIR = Path("/run/transume")
SECRET_WAIT_SECONDS = 10.0
_IMAGE_INPUT_OPERATIONS = frozenset({
    JobOperation.RESTOREDISK, JobOperation.RESTOREPARTS, JobOperation.CHECK_IMAGE,
})


class ResourceJournal:
    """Durable, runner-owned record of resources that may need recovery."""
    def __init__(self, runtime_dir: Path, job_id: str) -> None:
        if not job_id or "/" in job_id or job_id in {".", ".."}:
            raise RunnerValidationError("invalid resource journal job ID")
        self.path = runtime_dir / "journals" / f"{job_id}.json"
        self.data = {
            "job_id": job_id, "pid": os.getpid(), "start_time": _process_start_time(os.getpid()),
            "boot_id": _boot_id(), "state": "running", "resources": [],
        }
        self._write()

    def record(self, kind: str, path: Path, state: str) -> None:
        resources = self.data["resources"]
        assert isinstance(resources, list)
        resources.append({"kind": kind, "path": str(path), "state": state})
        self._write()

    def complete(self, success: bool) -> None:
        self.data["state"] = "complete" if success else "cleanup-failed"
        self._write()

    def _write(self) -> None:
        self.path.parent.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        runtime = self.path.parent.parent.lstat()
        expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
        if (stat.S_ISLNK(runtime.st_mode) or not stat.S_ISDIR(runtime.st_mode)
                or runtime.st_uid != expected_owner):
            raise RunnerValidationError("invalid runner runtime directory", "resource-journal-unavailable")
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        directory = self.path.parent.lstat()
        if (stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != expected_owner):
            raise RunnerValidationError("invalid resource journal directory", "resource-journal-unavailable")
        os.chmod(self.path.parent, 0o700)
        fd, temporary = tempfile.mkstemp(prefix=".journal-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, json.dumps(self.data, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
            os.fsync(fd)
            os.close(fd)
            os.replace(temporary, self.path)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


def recover_resource_journals(runtime_dir: Path, *, execute: Callable[..., object] = subprocess.run) -> None:
    """Recover stale job-owned bind mounts without trusting journal paths."""
    journals = runtime_dir / "journals"
    try:
        entries = tuple(journals.glob("*.json"))
    except OSError as exc:
        raise RunnerValidationError("resource journal recovery is unavailable", "resource-recovery-failed") from exc
    expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
    for path in entries:
        try:
            info = path.lstat()
            value = json.loads(path.read_text(encoding="ascii"))
        except (OSError, ValueError) as exc:
            raise RunnerValidationError("invalid resource journal", "resource-recovery-failed") from exc
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != expected_owner or stat.S_IMODE(info.st_mode) != 0o600):
            raise RunnerValidationError("invalid resource journal", "resource-recovery-failed")
        required = {"job_id", "pid", "start_time", "boot_id", "state", "resources"}
        if (not isinstance(value, dict) or set(value) != required
                or not isinstance(value["job_id"], str) or path.stem != value["job_id"]
                or type(value["pid"]) is not int or not isinstance(value["start_time"], str)
                or not isinstance(value["boot_id"], str) or not isinstance(value["state"], str)
                or not isinstance(value["resources"], list)):
            raise RunnerValidationError("invalid resource journal", "resource-recovery-failed")
        if value["state"] in {"complete", "recovered"}:
            continue
        try:
            active = (value["boot_id"] == _boot_id()
                      and value["start_time"] == _process_start_time(value["pid"]))
        except RunnerValidationError:
            active = False
        if active:
            continue
        expected = runtime_dir / "jobs" / value["job_id"]
        for resource in value["resources"]:
            if (not isinstance(resource, dict)
                    or set(resource) != {"kind", "path", "state"}
                    or resource["kind"] != "bind-mount"
                    or Path(resource["path"]) != expected):
                raise RunnerValidationError("invalid resource journal resource", "resource-recovery-failed")
        failed = False
        if os.path.ismount(expected):
            result = execute(("/bin/umount", "--", str(expected)), shell=False,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            failed = getattr(result, "returncode", result if isinstance(result, int) else 1) != 0
        try:
            expected.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            failed = True
        if failed:
            raise RunnerValidationError("stale resource cleanup failed", "resource-recovery-failed")
        value["state"] = "recovered"
        fd, temporary = tempfile.mkstemp(prefix=".journal-recovery-", dir=journals)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
            os.fsync(fd)
            os.close(fd)
            os.replace(temporary, path)
        except BaseException:
            try: os.close(fd)
            except OSError: pass
            try: os.unlink(temporary)
            except FileNotFoundError: pass
            raise


def run_job(spec: PublicJobSpec, *, authorized: bool, dry_run: bool = False,
              resolve_identity: Callable[[DeviceIdentity], DeviceIdentity] | None = None,
              execute: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
               on_output: Callable[[str], None] | None = None,
               cancel_event: threading.Event | None = None,
               popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
                   passphrase: bytearray | None = None,
                  runtime_dir: Path = RUNTIME_DIR,
                  preflight_service: PreflightService | None = None,
                   scope_manager: "RepositoryScopeManager | None" = None) -> RunResult:
    command = build_command(spec)
    needs_secret = _needs_secret(spec)
    if not dry_run and needs_secret != (passphrase is not None):
        raise RunnerValidationError("encryption secret is unavailable")
    if passphrase is not None and not _valid_passphrase(passphrase):
        passphrase[:] = b"\0" * len(passphrase)
        passphrase.clear()
        raise RunnerValidationError("encryption secret is unavailable")
    if command.destructive and not authorized:
        raise RunnerValidationError("destructive job is not authorized", "authorization-failed")
    if command.destructive and resolve_identity is None:
        raise RunnerValidationError("destructive job requires identity revalidation")
    if resolve_identity is not None:
        for expected in (*spec.sources, *spec.destinations):
            if resolve_identity(expected) != expected:
                raise RunnerValidationError(f"device identity changed: {expected.path}")
    if dry_run:
        return RunResult(command.argv, None, True)
    if cancel_event is not None and cancel_event.is_set():
        return RunResult(command.argv, None, False, cancelled=True)
    # Identity validation above prevents TOCTOU device replacement.  The shared
    # service then checks the current image, repository and target state before spawn.
    # The command builder uses absolute program paths; its exec failure is the
    # authoritative availability check.  Injected services can additionally
    # enforce capability probes in production/tests without making unit runners
    # depend on the host's Clonezilla installation.
    # Test executors model a process boundary and can supply an explicit service;
    # do not make those hermetic command-construction tests depend on host paths.
    if preflight_service is not None or execute is subprocess.run:
        service = preflight_service or PreflightService(binaries=lambda _name: "validated",
                                                        device_state=_current_devices)
        report = service.check(spec)
        if not report.ok:
            raise RunnerValidationError(next(issue.message for issue in report.issues
                                             if issue.severity.value == "error"))
    if cancel_event is not None and cancel_event.is_set():
        return RunResult(command.argv, None, False, cancelled=True)
    try:
        manager = scope_manager or RepositoryScopeManager(runtime_dir)
        # The bind mount refers to the already-open directory inode, so a later
        # rename or symlink swap cannot change what Clonezilla receives.
        # Hermetic injected executors do not model mount privileges. Production
        # execution and explicit scope-manager tests always take the pinned path.
        pinned = scope_manager is not None or execute is subprocess.run
        scope = manager.scope(spec) if pinned else _no_scope()
        with scope as pinned_repository:
            execution_spec = replace(spec, repository=pinned_repository) if pinned_repository else spec
            if pinned:
                _validate_image_evidence(execution_spec)
            command = build_command(execution_spec)
            if passphrase is None:
                result = _execute_command(command, execute, on_output, cancel_event, popen)
            else:
                with _passphrase_file(passphrase, runtime_dir) as path:
                    # Clonezilla consumes this only as the argument after -pfe.
                    private_argv = _inject_passphrase_file(command.argv, path)
                    private_command = Command(private_argv, command.destructive, command.environment, command.cwd)
                    secret_text = passphrase.decode("utf-8", "ignore")
                    result = _execute_command(
                        private_command, execute, on_output, cancel_event, popen,
                        secrets=(secret_text,),
                    )
        result = replace(result, cleanup=manager.cleanup_status)
        return result
    finally:
        if passphrase is not None:
            passphrase[:] = b"\0" * len(passphrase)
            passphrase.clear()


def _validate_image_evidence(spec: PublicJobSpec) -> None:
    if spec.operation not in _IMAGE_INPUT_OPERATIONS:
        return
    if not spec.repository or not spec.image_name or not spec.image_fingerprint:
        raise RunnerValidationError("image operation requires image evidence")
    try:
        image = (Path(spec.repository) / spec.image_name).resolve(strict=True)
        image.relative_to(Path(spec.repository).resolve(strict=True))
        if image_fingerprint(image) != spec.image_fingerprint:
            raise RunnerValidationError("image changed after selection")
        parsed = parse_clonezilla_image(image)
        if parsed.status is ImageStatus.ENCRYPTED:
            if not spec.options.get("encrypted") or not parsed.topology.disks:
                raise RunnerValidationError("encrypted image topology is unavailable")
        elif spec.options.get("encrypted"):
            raise RunnerValidationError("encrypted image evidence changed")
    except RunnerValidationError:
        raise
    except (OSError, ValueError) as exc:
        raise RunnerValidationError("image evidence is unavailable") from exc


class RepositoryScopeManager:
    """Create a root-owned bind mount of an opened repository directory."""
    def __init__(self, runtime_dir: Path, *, execute: Callable[..., object] = subprocess.run,
                 journal: ResourceJournal | None = None) -> None:
        self.runtime_dir, self.execute = runtime_dir, execute
        self.journal = journal
        self.cleanup_status = "not-needed"

    @contextmanager
    def scope(self, spec: PublicJobSpec):
        if not spec.repository:
            yield None
            return
        fd: int | None = None
        path: Path | None = None
        mounted = False
        self.cleanup_status = "failed"
        try:
            fd = os.open(spec.repository, os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_PATH", os.O_RDONLY))
            if not stat.S_ISDIR(os.fstat(fd).st_mode) or "/" in spec.job_id or spec.job_id in {".", ".."}:
                raise RunnerValidationError("invalid repository scope")
            self._prepare_jobs_dir()
            jobs = self.runtime_dir / "jobs"
            path = jobs / spec.job_id
            path.mkdir(mode=0o700)
            if self.journal is not None:
                self.journal.record("bind-mount", path, "prepared")
            # mount runs in a child; refer to this runner's still-open descriptor.
            result = self.execute(("/bin/mount", "--bind", f"/proc/{os.getpid()}/fd/{fd}", str(path)), shell=False,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                                  env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            if getattr(result, "returncode", result if isinstance(result, int) else 1) != 0:
                raise RunnerValidationError("repository pinning is unavailable")
            mounted = True
            if self.journal is not None:
                self.journal.record("bind-mount", path, "mounted")
            yield str(path)
        finally:
            failed = False
            if mounted and path is not None:
                try:
                    result = self.execute(("/bin/umount", "--", str(path)), shell=False,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
                    failed = getattr(result, "returncode", result if isinstance(result, int) else 1) != 0
                except Exception:
                    failed = True
            if path is not None:
                try: path.rmdir()
                except OSError: failed = True
            if self.journal is not None and path is not None:
                self.journal.record("bind-mount", path, "released" if not failed else "cleanup-failed")
            if fd is not None:
                os.close(fd)
            self.cleanup_status = "failed" if failed else "complete"
            if self.journal is not None:
                self.journal.complete(not failed)

    def _prepare_jobs_dir(self) -> None:
        expected_owner = 0
        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        runtime_info = self.runtime_dir.lstat()
        if (stat.S_ISLNK(runtime_info.st_mode) or not stat.S_ISDIR(runtime_info.st_mode)
                or runtime_info.st_uid != expected_owner):
            raise RunnerValidationError("invalid runner runtime directory")
        jobs = self.runtime_dir / "jobs"
        jobs.mkdir(mode=0o700, exist_ok=True)
        jobs_info = jobs.lstat()
        if (stat.S_ISLNK(jobs_info.st_mode) or not stat.S_ISDIR(jobs_info.st_mode)
                or jobs_info.st_uid != expected_owner or stat.S_IMODE(jobs_info.st_mode) != 0o700):
            raise RunnerValidationError("invalid runner jobs directory")


@contextmanager
def _no_scope():
    yield None


def _execute_command(command: Command, execute, on_output, cancel_event, popen, *, secrets: tuple[str, ...] = ()) -> RunResult:
    if on_output is not None and execute is subprocess.run:
        sink = lambda line: on_output(redact_text(line, secrets=secrets))
        return _run_streaming(command, sink, cancel_event=cancel_event, popen=popen,
                              retain_output=True)
    completed = execute(command.argv, shell=False, stdin=subprocess.DEVNULL,
                        capture_output=True, env=dict(command.environment), check=False,
                        cwd=command.cwd)
    stdout = completed.stdout.decode("utf-8", "replace") if isinstance(completed.stdout, bytes) else (completed.stdout or "")
    stderr = completed.stderr.decode("utf-8", "replace") if isinstance(completed.stderr, bytes) else (completed.stderr or "")
    return RunResult(command.argv, completed.returncode, False,
                     redact_text(stdout, secrets=secrets), redact_text(stderr, secrets=secrets))


class _PassphraseFile:
    def __init__(self, value: bytearray, runtime_dir: Path):
        self.value = value
        self.runtime_dir = runtime_dir
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.runtime_dir, 0o700)
        fd, name = tempfile.mkstemp(prefix="ecryptfs-", dir=self.runtime_dir)
        self.path = Path(name)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, b"passphrase_passwd=" + self.value + b"\n")
        finally:
            os.close(fd)
        return self.path

    def __exit__(self, *_: object) -> None:
        if self.path is not None:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass


def _passphrase_file(value: bytearray, runtime_dir: Path) -> _PassphraseFile:
    return _PassphraseFile(value, runtime_dir)


def _valid_passphrase(value: bytearray) -> bool:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(text) and len(text) <= 4096 and not any(character in text for character in "\x00\r\n")


def _needs_secret(spec: PublicJobSpec) -> bool:
    return ((spec.operation in {JobOperation.SAVEDISK, JobOperation.SAVEPARTS}
             and spec.options.get("encrypt") is True)
            or (spec.operation in {JobOperation.RESTOREDISK, JobOperation.RESTOREPARTS}
                and spec.options.get("encrypted") is True))


def _inject_passphrase_file(argv: tuple[str, ...], path: Path) -> tuple[str, ...]:
    try:
        operation = next(index for index, value in enumerate(argv)
                         if value in {"savedisk", "saveparts", "restoredisk", "restoreparts"})
    except StopIteration as exc:
        raise RunnerValidationError("encrypted Clonezilla operation is invalid") from exc
    return (*argv[:operation], "-pfe", str(path), *argv[operation:])


def _run_streaming(command: Command, on_output: Callable[[str], None], *,
                   cancel_event: threading.Event | None,
                   popen: Callable[..., subprocess.Popen[str]],
                   terminate_timeout: float = 5.0, retain_output: bool = True) -> RunResult:
    process = popen(
        command.argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=dict(command.environment),
        cwd=command.cwd,
        start_new_session=True,
        bufsize=1,
    )
    lines: list[str] = []
    retained_bytes = 0
    output: queue.Queue[str | None] = queue.Queue()
    assert process.stdout is not None

    def drain() -> None:
        for line in process.stdout:
            output.put(line)
        output.put(None)

    reader = threading.Thread(target=drain, name="transume-output", daemon=True)
    reader.start()
    cancelled = False
    deadline: float | None = None
    output_closed = False
    post_exit_deadline: float | None = None
    while not output_closed or process.poll() is None:
        if process.poll() is not None and not output_closed:
            post_exit_deadline = post_exit_deadline or time.monotonic() + 1.0
            if time.monotonic() >= post_exit_deadline:
                break
        if cancel_event is not None and cancel_event.is_set() and not cancelled:
            cancelled = True
            # start_new_session makes the child and any descendants one killable group.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + terminate_timeout
        if cancelled and deadline is not None and time.monotonic() >= deadline and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = None
        try:
            line = output.get(timeout=0.1)
        except queue.Empty:
            continue
        if line is None:
            output_closed = True
            continue
        clean = line.rstrip("\r\n")
        if retain_output:
            encoded = len(clean.encode("utf-8", "replace"))
            lines.append(clean)
            retained_bytes += encoded
            while len(lines) > 1000 or retained_bytes > 1_048_576:
                retained_bytes -= len(lines.pop(0).encode("utf-8", "replace"))
        on_output(clean)
    returncode = process.wait()
    reader.join(timeout=1)
    return RunResult(command.argv, returncode, False, "\n".join(lines), "", cancelled)


def resolve_device_identity(expected: DeviceIdentity) -> DeviceIdentity:
    """Rebuild identity from current sysfs, udev and lsblk evidence; fail closed."""
    try:
        info = os.stat(expected.path)
    except OSError as exc:
        raise RunnerValidationError(f"device is unavailable: {expected.path}") from exc
    if not stat.S_ISBLK(info.st_mode):
        raise RunnerValidationError(f"not a block device: {expected.path}")
    major_minor = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    if major_minor != expected.major_minor:
        raise RunnerValidationError(f"device number changed: {expected.path}")
    sysfs = Path("/sys/dev/block") / major_minor
    try:
        current_sysfs = str(sysfs.resolve(strict=True))
        expected_sysfs = str(Path(expected.sysfs_path).resolve(strict=True))
    except OSError as exc:
        raise RunnerValidationError(f"sysfs identity is unavailable: {expected.path}") from exc
    if current_sysfs != expected_sysfs:
        raise RunnerValidationError(f"sysfs identity changed: {expected.path}")
    try:
        current_size = int((sysfs / "size").read_text(encoding="ascii").strip()) * 512
    except (OSError, ValueError) as exc:
        raise RunnerValidationError(f"device size is unavailable: {expected.path}") from exc
    if current_size != expected.size:
        raise RunnerValidationError(f"device size changed: {expected.path}")

    result = subprocess.run(
        ("/usr/bin/udevadm", "info", "--query=property", "--name", expected.path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if result.returncode != 0:
        raise RunnerValidationError(f"udev evidence is unavailable: {expected.path}")
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    current_serial = properties.get("ID_SERIAL_SHORT") or properties.get("ID_SERIAL")
    current_wwn = properties.get("ID_WWN_WITH_EXTENSION") or properties.get("ID_WWN")
    if expected.serial and expected.serial != current_serial:
        raise RunnerValidationError(f"device serial changed: {expected.path}")
    if expected.wwn and expected.wwn != current_wwn:
        raise RunnerValidationError(f"device WWN changed: {expected.path}")
    try:
        current = {item.path: item for item in _current_devices()}[expected.path].identity()
    except (KeyError, RuntimeError, ValueError) as exc:
        raise RunnerValidationError(f"device scan evidence is unavailable: {expected.path}") from exc
    # Equality is intentionally checked field by field: omitted historical fields
    # do not invent evidence, while every supplied stable value must still match.
    for name in ("path", "major_minor", "sysfs_path", "device_type", "size", "parent_chain",
                 "serial", "wwn", "by_id", "vendor", "model", "partition_table_type",
                 "partition_table_uuid", "partition_uuids", "relationships", "removable", "transport"):
        wanted, actual = getattr(expected, name), getattr(current, name)
        if wanted not in (None, (), False) and wanted != actual:
            raise RunnerValidationError(f"device identity changed: {expected.path}")
    return expected


def _validate_device_state(spec: PublicJobSpec) -> None:
    devices = {}

    def collect(item: BlockDevice) -> None:
        devices[item.path] = item
        for child in item.children:
            collect(child)

    for root in scan_block_devices():
        collect(root)
    for identity in (*spec.sources, *spec.destinations):
        current = devices.get(identity.path)
        if current is None:
            raise RunnerValidationError(f"device disappeared: {identity.path}")
        if current.is_mounted:
            raise RunnerValidationError(f"device is mounted: {identity.path}")
        if current.is_swap:
            raise RunnerValidationError(f"device is active swap: {identity.path}")
        if current.is_system or current.is_live:
            raise RunnerValidationError(f"system/live device is blocked: {identity.path}")
        if current.read_only and identity in spec.destinations:
            raise RunnerValidationError(f"device is read-only: {identity.path}")
        if identity in spec.sources and current.read_only and spec.operation not in {
                JobOperation.SAVEDISK, JobOperation.SAVEPARTS, JobOperation.CLONE_DISK,
                JobOperation.CLONE_PART}:
            raise RunnerValidationError(f"source is read-only: {identity.path}")


def _current_devices() -> tuple[BlockDevice, ...]:
    result: list[BlockDevice] = []
    def collect(item: BlockDevice) -> None:
        result.append(item)
        for child in item.children:
            collect(child)
    for root in scan_block_devices():
        collect(root)
    return tuple(result)


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RunnerValidationError("boot identity is unavailable", "lock-metadata-unavailable") from exc


def _process_start_time(pid: int) -> str:
    try:
        # The comm field may contain spaces and parentheses; field 22 follows its final ')'.
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rpartition(")")[2].split()
        return fields[19]
    except (OSError, IndexError) as exc:
        raise RunnerValidationError("process start time is unavailable", "lock-metadata-unavailable") from exc


def _lock_is_stale(value: object) -> bool:
    if not isinstance(value, dict):
        return True
    try:
        pid = value["pid"]
        return (not isinstance(pid, int) or isinstance(pid, bool)
                or value.get("boot_id") != _boot_id()
                or value.get("start_time") != _process_start_time(pid))
    except RunnerValidationError:
        return True


def _acquire_lock(job_id: str, *, path: Path = LOCK_PATH) -> object:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    handle = path.open("a+", encoding="ascii")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise RunnerValidationError("another privileged disk job is active", "job-lock-active") from exc
    try:
        handle.seek(0)
        previous = json.load(handle)
    except (json.JSONDecodeError, OSError):
        previous = None
    # An unlocked record is diagnostic only. Verify it before replacing it so stale
    # lock files never become an authority over a new kernel-held flock.
    _lock_is_stale(previous)
    handle.seek(0)
    handle.truncate()
    json.dump({"pid": os.getpid(), "start_time": _process_start_time(os.getpid()),
               "boot_id": _boot_id(), "job_id": job_id}, handle,
              ensure_ascii=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
    return handle


def _enter_private_mount_namespace() -> None:
    """Prevent runner-owned mounts from propagating outside this one-shot runner."""
    try:
        os.unshare(getattr(os, "CLONE_NEWNS", 0x00020000))
        result = subprocess.run(("/bin/mount", "--make-rprivate", "/"), shell=False,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (AttributeError, OSError) as exc:
        raise RunnerValidationError("private mount namespace is unavailable", "mount-namespace-unavailable") from exc
    if result.returncode != 0:
        raise RunnerValidationError("private mount namespace is unavailable", "mount-namespace-unavailable")


def _validate_action(action: str, spec: PublicJobSpec) -> None:
    if action == "check" and spec.operation.value != "check-image":
        raise RunnerValidationError("read-only policy action cannot run this job")
    if action == "write" and spec.operation.value == "check-image":
        raise RunnerValidationError("job does not match the write policy action")


def caller_identity(*, caller_uid: int | None = None, dry_run: bool = False) -> tuple[int, int]:
    """Return the desktop identity asserted by pkexec, never by the IPC client."""
    if caller_uid is None:
        value = os.environ.get("PKEXEC_UID")
        if value is None:
            if not dry_run:
                raise RunnerValidationError("mount caller identity is unavailable")
            caller_uid = os.getuid()
        elif not value.isdecimal() or value != str(int(value)):
            raise RunnerValidationError("mount caller identity is invalid")
        else:
            caller_uid = int(value)
    if isinstance(caller_uid, bool) or not isinstance(caller_uid, int) or caller_uid < 1000:
        raise RunnerValidationError("mount caller identity is invalid")
    try:
        account = pwd.getpwuid(caller_uid)
    except KeyError as exc:
        raise RunnerValidationError("mount caller identity is invalid") from exc
    if account.pw_uid != caller_uid or account.pw_gid == 0:
        raise RunnerValidationError("mount caller identity is invalid")
    return account.pw_uid, account.pw_gid


def run_storage_request(request: StorageRequest, *, storage: PrivilegedStorage | None = None,
                        caller_uid: int | None = None, dry_run: bool = False):
    """Execute a storage request without exposing its private fields to job handling."""
    uid, gid = caller_identity(caller_uid=caller_uid, dry_run=dry_run)
    return (storage or PrivilegedStorage(caller_uid=uid, caller_gid=gid)).handle(request)


def run_explorer_request(request: ExplorerRequest, *, explorer: ImageExplorer | None = None,
                         caller_uid: int | None = None, dry_run: bool = False):
    """Explorer is deliberately isolated from jobs and storage request parsing."""
    uid, gid = caller_identity(caller_uid=caller_uid, dry_run=dry_run)
    return (explorer or ImageExplorer(caller_uid=uid, caller_gid=gid)).handle(request)


def serve_once(*, action: str, dry_run: bool = False, secret_wait_seconds: float = SECRET_WAIT_SECONDS,
               runtime_dir: Path = RUNTIME_DIR) -> int:
    input_stream = sys.stdin.buffer
    output_stream = sys.stdout.buffer
    hello = read_message(input_stream)
    if hello["type"] != "hello":
        raise RunnerValidationError("protocol must start with hello")
    write_message(output_stream, {"type": "hello", "version": PROTOCOL_VERSION})
    message = read_message(input_stream)
    if action == "mount":
        if message["type"] not in {"storage-request", "explorer-request"}:
            raise RunnerValidationError("expected one mount request")
        if not dry_run and os.geteuid() != 0:
            raise RunnerValidationError("runner must be authorized through PolicyKit", "authorization-failed")
        if message["type"] == "storage-request":
            request = StorageRequest.from_dict(message["request"])
        else:
            request = ExplorerRequest.from_dict(message["request"])
        if dry_run:
            caller_identity(dry_run=True)
            result = {"request_id": request.request_id, "status": "ok", "root": None,
                      "detail": "validated"}
        else:
            value = run_storage_request(request) if isinstance(request, StorageRequest) else run_explorer_request(request)
            result = {"request_id": value.request_id, "status": value.status,
                      "root": getattr(value, "root", None), "detail": value.detail}
            if not isinstance(request, StorageRequest):
                result.update({"session_id": value.session_id, "mountpoint": value.mountpoint})
        kind = "storage-result" if isinstance(request, StorageRequest) else "explorer-result"
        if isinstance(request, StorageRequest):
            result["error_code"] = None if dry_run else value.error_code
        write_message(output_stream, {"type": kind, "version": PROTOCOL_VERSION, **result})
        return 0 if result["status"] in {"ok", "not-mounted"} else 1
    if message["type"] != "job":
        raise RunnerValidationError("expected one job")
    spec = PublicJobSpec.from_dict(message["spec"])
    _validate_action(action, spec)
    authorized = os.geteuid() == 0
    if not dry_run and not authorized:
        raise RunnerValidationError("runner must be authorized through PolicyKit", "authorization-failed")
    if not dry_run:
        _enter_private_mount_namespace()
    needs_secret = _needs_secret(spec)
    secret: bytearray | None = None
    if needs_secret and not dry_run:
        try:
            secret_message = _read_secret(input_stream, secret_wait_seconds)
            if secret_message["type"] != "secret":
                raise ValueError("unexpected frame")
            secret = bytearray(secret_message["value"].encode("utf-8"))
        except (EOFError, ValueError, queue.Empty):
            raise RunnerValidationError("encryption secret is unavailable") from None
    lock = _acquire_lock(spec.job_id) if not dry_run else None
    if not dry_run:
        recover_resource_journals(runtime_dir)
    parser = ProgressParser()
    cancelled = threading.Event()
    fatal_events: list[str] = []

    def watch_for_cancel() -> None:
        """The runner is the only stdin reader after the job frame."""
        try:
            while True:
                message = read_message(input_stream)
                if message["type"] == "cancel":
                    cancelled.set()
                    return
                # A one-shot runner accepts no more jobs; ignore valid late frames.
        except (EOFError, ValueError):
            return

    if not dry_run:
        threading.Thread(target=watch_for_cancel, name="transume-cancel", daemon=True).start()

    def emit(line: str) -> None:
        secret_text = secret.decode("utf-8", "ignore") if secret else ""
        event = parser.feed_line(redact_text(line, secrets=((secret_text,) if secret_text else ())))
        if event.kind == "error":
            fatal_events.append(event.message)
        write_message(output_stream, {
            "type": "progress", "version": PROTOCOL_VERSION,
            "kind": event.kind, "message": event.message,
            "percent": event.percent, "device": event.device, "rate": event.rate,
        })

    try:
        journal = ResourceJournal(runtime_dir, spec.job_id) if not dry_run else None
        try:
            result = run_job(
                spec,
                authorized=authorized or dry_run,
                dry_run=dry_run,
                resolve_identity=resolve_device_identity if not dry_run else (lambda value: value),
                on_output=emit if not dry_run else None,
                cancel_event=cancelled,
                passphrase=secret,
                runtime_dir=runtime_dir,
                scope_manager=RepositoryScopeManager(runtime_dir, journal=journal) if journal else None,
            )
        except BaseException:
            if journal is not None and journal.data["state"] == "running":
                journal.complete(False)
            raise
        else:
            if journal is not None and journal.data["state"] == "running":
                journal.complete(result.cleanup != "failed")
    finally:
        if lock is not None:
            lock.close()
    effective_exit_code = 1 if fatal_events and result.returncode == 0 else result.returncode
    status = "dry-run" if result.dry_run else ("cancelled" if result.cancelled else ("ok" if effective_exit_code == 0 else "failed"))
    if result.dry_run:
        detail = " ".join(result.argv)
    elif result.cancelled:
        detail = "cancelled by client"
    elif fatal_events and result.returncode == 0:
        detail = redact_text(f"Clonezilla reported an error: {fatal_events[-1]}")
    elif result.returncode == 0:
        detail = "completed successfully"
    else:
        output = (result.stderr or result.stdout).strip()[-4000:]
        secret_text = secret.decode("utf-8", "ignore") if secret else ""
        detail = redact_text(f"exit status {result.returncode}: {output}",
                             secrets=((secret_text,) if secret_text else ()))
    write_message(output_stream, {
        "type": "result", "version": PROTOCOL_VERSION,
        "status": status, "detail": detail,
        "error_code": (None if status in {"dry-run", "ok"} else
                       "cancelled" if status == "cancelled" else
                       "clonezilla-reported-error" if fatal_events and result.returncode == 0 else
                       "clonezilla-failed"), "exit_code": effective_exit_code,
        "verification": "passed" if status == "ok" and spec.operation.value == "check-image" else "not-run",
        "cleanup": result.cleanup if not result.dry_run else "not-needed",
    })
    return 0 if status in {"dry-run", "ok"} else 1


def _read_secret(stream, timeout: float) -> dict:
    """Bound the pre-execution private frame wait without exposing its content."""
    received: queue.Queue[dict | BaseException] = queue.Queue(maxsize=1)

    def read() -> None:
        try:
            received.put(read_message(stream))
        except (EOFError, ValueError) as error:
            received.put(error)

    threading.Thread(target=read, name="transume-secret", daemon=True).start()
    value = received.get(timeout=timeout)
    if isinstance(value, BaseException):
        raise value
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Transume one-shot privileged runner")
    parser.add_argument("action", choices=("mount", "check", "write"))
    parser.add_argument("--stdio", action="store_true", help="serve one framed-JSON job")
    parser.add_argument("--dry-run", action="store_true", help="validate without executing")
    args = parser.parse_args(argv)
    if not args.stdio:
        parser.error("--stdio is required")
    try:
        return serve_once(action=args.action, dry_run=args.dry_run)
    except RunnerValidationError as exc:
        try:
            write_message(sys.stdout.buffer, {
                "type": "result", "version": PROTOCOL_VERSION,
                "status": "failed", "detail": str(exc), "error_code": exc.code, "exit_code": None,
                "verification": None, "cleanup": None,
            })
        except (BrokenPipeError, ValueError):
            pass
        return 2
    except (EOFError, ValueError, OSError, subprocess.SubprocessError) as exc:
        try:
            write_message(sys.stdout.buffer, {
                "type": "result", "version": PROTOCOL_VERSION,
                "status": "failed", "detail": "runner request failed", "error_code": "request-failed", "exit_code": None,
                "verification": None, "cleanup": None,
            })
        except (BrokenPipeError, ValueError):
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
