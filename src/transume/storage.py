"""Storage locations and safe lifecycle management for their mounts."""

from __future__ import annotations

import ipaddress
import os
import pwd
import re
import shutil
import stat
import tempfile
import base64
import fcntl
import hashlib
import subprocess
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
from uuid import uuid4


class StorageKind(StrEnum):
    LOCAL_FOLDER = "local-folder"
    MOUNTED_FILESYSTEM = "mounted-filesystem"
    BLOCK_DEVICE = "block-device"
    REMOVABLE = "removable"
    SMB = "smb"
    NFS = "nfs"
    SSH = "ssh"


class ConnectionState(StrEnum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    MOUNTED = "mounted"
    UNMOUNTING = "unmounting"
    FAILED = "failed"


class MountOwnership(StrEnum):
    EXTERNAL = "external"
    TRANSUME = "transume"


class StorageError(RuntimeError):
    """A deterministic failure while validating or changing storage state."""

    def __init__(self, message: str, code: str = "operation-failed") -> None:
        super().__init__(message)
        self.code = code


_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SSH_KEY_TYPES = frozenset({"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"})


def normalized_known_host_token(host: str, port: int | None = None) -> str:
    """Return the only known_hosts token accepted for this SSH endpoint."""
    _validate_host(host)
    value = host.strip("[]")
    try:
        value = ipaddress.ip_address(value).compressed
    except ValueError:
        value = value.lower()
    actual_port = port or 22
    return value if actual_port == 22 else f"[{value}]:{actual_port}"


def parse_ssh_host_key(line: str, token: str | None = None) -> tuple[str, str]:
    """Validate a single, unhashed known_hosts entry and return its key fields."""
    if not isinstance(line, str) or len(line) > 8192 or any(ch in line for ch in "\x00\r\n"):
        raise ValueError("invalid SSH host key")
    fields = line.split(" ")
    if len(fields) != 3 or not all(fields) or fields[0].find(",") >= 0:
        raise ValueError("invalid SSH host key")
    host, key_type, encoded = fields
    if token is not None and host != token:
        raise ValueError("SSH host key does not match host")
    if key_type not in _SSH_KEY_TYPES:
        raise ValueError("unsupported SSH host key type")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid SSH host key") from exc
    if not 16 <= len(decoded) <= 16384:
        raise ValueError("invalid SSH host key")
    return key_type, encoded


def ssh_host_key_fingerprint(line: str) -> str:
    _, encoded = parse_ssh_host_key(line)
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(encoded)).digest()).decode("ascii").rstrip("=")


def scan_ssh_host_keys(host: str, port: int | None, *, run: Callable[..., object] = subprocess.run,
                       timeout: float = 10.0) -> tuple[str, ...]:
    token = normalized_known_host_token(host, port)
    argv = ["/usr/bin/ssh-keyscan", "-T", str(max(1, int(timeout)))]
    if port:
        argv.extend(("-p", str(port)))
    argv.append(host.strip("[]"))
    result = run(tuple(argv), shell=False, capture_output=True, text=True, timeout=timeout,
                 check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if getattr(result, "returncode", 1) != 0:
        raise StorageError("SSH host key scan failed")
    keys = []
    for line in getattr(result, "stdout", "").splitlines():
        try:
            parse_ssh_host_key(line, token)
        except ValueError:
            continue
        keys.append(line)
    unique = tuple(dict.fromkeys(keys))
    if not unique:
        raise StorageError("SSH host key scan returned no valid key")
    return unique


@dataclass(frozen=True, slots=True)
class StorageRequest:
    """Private, one-shot request sent only over the runner's framed pipe."""

    request_id: str
    operation: str
    location: StorageLocation
    credentials: Mapping[str, str] = field(default_factory=dict, repr=False)
    read_only: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not _REQUEST_ID.fullmatch(self.request_id):
            raise ValueError("invalid storage request id")
        if not isinstance(self.location, StorageLocation):
            raise ValueError("invalid storage location")
        if self.operation not in {"mount", "unmount"}:
            raise ValueError("invalid storage operation")
        if not isinstance(self.read_only, bool):
            raise ValueError("read_only must be boolean")
        credentials = dict(self.credentials)
        if self.operation == "unmount" and credentials:
            raise ValueError("unmount credentials are forbidden")
        if self.location.kind is StorageKind.SSH:
            if set(credentials) - {"auth_method", "password", "host_key", "identity_file", "agent_socket"}:
                raise ValueError("SSH credentials contain unsupported fields")
            method = credentials.get("auth_method")
            if method is not None and method not in {"password", "private-key", "agent"}:
                raise ValueError("invalid SSH authentication method")
            if method == "password" and ("password" not in credentials
                    or set(credentials) - {"auth_method", "password", "host_key"}):
                raise ValueError("invalid password authentication credentials")
            if method == "private-key" and ("identity_file" not in credentials
                    or set(credentials) - {"auth_method", "identity_file", "host_key"}):
                raise ValueError("invalid private-key authentication credentials")
            if method == "agent" and ("agent_socket" not in credentials
                    or set(credentials) - {"auth_method", "agent_socket", "host_key"}):
                raise ValueError("invalid SSH agent credentials")
            if "host_key" in credentials:
                parse_ssh_host_key(credentials["host_key"], normalized_known_host_token(self.location.host or "", self.location.port))
        elif self.location.kind is not StorageKind.SMB and credentials:
            raise ValueError("credentials are supported only for SMB")
        if any(not isinstance(key, str) or not isinstance(value, str) or not key
               or not value or any(ch in key or ch in value for ch in "\x00\r\n")
               for key, value in credentials.items()):
            raise ValueError("invalid credentials")
        object.__setattr__(self, "credentials", MappingProxyType(credentials))

    def to_dict(self) -> dict[str, Any]:
        return {"request_id": self.request_id, "operation": self.operation,
                "location": {"kind": self.location.kind.value, "root": self.location.root,
                             "host": self.location.host, "endpoint": self.location.endpoint,
                              "share": self.location.share, "device": self.location.device,
                              "username": self.location.username, "port": self.location.port},
                "credentials": dict(self.credentials), "read_only": self.read_only}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StorageRequest":
        required = {"request_id", "operation", "location", "credentials", "read_only"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise ValueError("missing or unknown StorageRequest fields")
        location = value["location"]
        fields = {"kind", "root", "host", "endpoint", "share", "device", "username", "port"}
        if not isinstance(location, Mapping) or set(location) != fields:
            raise ValueError("invalid StorageLocation fields")
        if not isinstance(value["credentials"], dict):
            raise ValueError("invalid credentials")
        return cls(value["request_id"], value["operation"],
                   StorageLocation(StorageKind(location["kind"]), **{k: v for k, v in location.items() if k != "kind"}),
                   value["credentials"], value["read_only"])


@dataclass(frozen=True, slots=True)
class StorageResult:
    request_id: str
    status: str
    root: str | None
    detail: str
    error_code: str | None = None


class PrivilegedStorage:
    """Runner-side mount owner. Its mount roots are never supplied by clients."""

    def __init__(self, *, base: Path = Path("/run/transume/mounts"),
                   runtime: Path = Path("/run/transume"), timeout: float = 30.0,
                   state: Path = Path("/var/lib/transume"),
                   execute: Callable[..., object] | None = None,
                   is_mount: Callable[[str], bool] | None = None,
                   mountinfo: Callable[[], str] | None = None,
                   which: Callable[..., str | None] = shutil.which,
                  caller_uid: int | None = None, caller_gid: int | None = None,
                  fuse_conf: Path = Path("/etc/fuse.conf")) -> None:
        self.base = base
        self.runtime = runtime
        self.state = state
        self.timeout = timeout
        self.execute = execute
        self.is_mount = is_mount or os.path.ismount
        self.mountinfo = mountinfo or self._read_mountinfo
        self.which = which
        if caller_uid is None:
            raise StorageError("mount caller identity is unavailable")
        try:
            account = pwd.getpwuid(caller_uid)
        except KeyError as exc:
            raise StorageError("mount caller identity is invalid") from exc
        if caller_uid == 0 or account.pw_uid != caller_uid:
            raise StorageError("mount caller identity is invalid")
        self.caller_uid = caller_uid
        self.caller_gid = account.pw_gid if caller_gid is None else caller_gid
        if self.caller_gid != account.pw_gid:
            raise StorageError("mount caller identity is invalid")
        self.fuse_conf = fuse_conf

    def handle(self, request: StorageRequest) -> StorageResult:
        try:
            return self._mount(request) if request.operation == "mount" else self._unmount(request)
        except StorageError as error:
            safe_details = {
                "SMB authentication failed", "SMB host is unreachable",
                "SMB share was not found", "SSH authentication failed",
                "SSH host is unreachable", "SSH path was not found",
                "NFS host is unreachable", "NFS export was not found",
                "storage command timed out", "SSH host key changed",
                "storage target is busy", "mounted filesystem does not match request",
            }
            code = error.code if error.code in {
                "authentication-failed", "host-unreachable", "resource-not-found",
                "protocol-mismatch", "timeout", "host-key-changed", "target-busy",
                "operation-failed",
            } else "operation-failed"
            detail = str(error) if str(error) in safe_details else "storage operation failed"
            return StorageResult(request.request_id, "failed", None, detail, code)
        except Exception:
            # Never turn subprocess diagnostics or credential validation values into IPC output.
            return StorageResult(request.request_id, "failed", None,
                                 "storage operation failed", "operation-failed")

    def _prepare_base(self) -> None:
        self.runtime.mkdir(mode=0o711, parents=True, exist_ok=True)
        self.base.mkdir(mode=0o711, parents=True, exist_ok=True)
        expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
        runtime_info = self.runtime.lstat()
        if (stat.S_ISLNK(runtime_info.st_mode) or not stat.S_ISDIR(runtime_info.st_mode)
                or runtime_info.st_uid != expected_owner):
            raise StorageError("invalid runtime root")
        os.chmod(self.runtime, 0o711)
        base_info = self.base.lstat()
        if (stat.S_ISLNK(base_info.st_mode) or not stat.S_ISDIR(base_info.st_mode)
                or base_info.st_uid != expected_owner):
            raise StorageError("invalid mount root")
        os.chmod(self.base, 0o711)

    def _root(self, request: StorageRequest) -> Path:
        root = self.base / request.request_id
        if root.parent != self.base or root.name != request.request_id:
            raise StorageError("invalid mount root")
        return root

    def _source(self, location: StorageLocation) -> str:
        if location.kind is StorageKind.SMB:
            assert location.host and location.share
            return f"//{location.host}/{location.share}"
        if location.kind is StorageKind.NFS:
            assert location.host and location.endpoint
            return f"{location.host}:{location.endpoint}"
        if location.kind is StorageKind.SSH:
            assert location.username and location.host and location.endpoint
            host = location.host
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            return f"{location.username}@{host}:{location.endpoint}"
        if location.kind in {StorageKind.BLOCK_DEVICE, StorageKind.REMOVABLE}:
            assert location.device
            return location.device
        raise StorageError("unsupported storage kind")

    def _run(self, argv: Sequence[str], input: bytes | None = None) -> None:
        try:
            if self.execute is not None:
                result = self.execute(tuple(argv), timeout=self.timeout, input=input)
            else:
                result = subprocess.run(tuple(argv), shell=False, input=input,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                        timeout=self.timeout, check=False,
                                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        except subprocess.TimeoutExpired as exc:
            raise StorageError("storage command timed out", "timeout") from exc
        if isinstance(result, int):
            code = result
        else:
            code = getattr(result, "returncode", 0)
        if code != 0:
            diagnostics = getattr(result, "stderr", b"")
            if isinstance(diagnostics, bytes):
                diagnostics = diagnostics.decode("utf-8", "replace")
            diagnostics = str(diagnostics).casefold()
            if len(argv) >= 3 and tuple(argv[:3]) == ("mount", "-t", "cifs"):
                if any(marker in diagnostics for marker in ("permission denied", "logon failure", "error(13)")):
                    raise StorageError("SMB authentication failed", "authentication-failed")
                if any(marker in diagnostics for marker in ("no route to host", "host is down", "error(112)", "error(113)")):
                    raise StorageError("SMB host is unreachable", "host-unreachable")
                if any(marker in diagnostics for marker in ("no such file", "bad network name", "error(2)")):
                    raise StorageError("SMB share was not found", "resource-not-found")
            if argv and argv[0] == "sshfs":
                if "permission denied" in diagnostics:
                    raise StorageError("SSH authentication failed", "authentication-failed")
                if any(marker in diagnostics for marker in ("no route to host", "could not resolve", "connection timed out")):
                    raise StorageError("SSH host is unreachable", "host-unreachable")
                if "no such file" in diagnostics:
                    raise StorageError("SSH path was not found", "resource-not-found")
            if len(argv) >= 3 and tuple(argv[:3]) == ("mount", "-t", "nfs"):
                if any(marker in diagnostics for marker in ("no route to host", "not responding", "connection timed out")):
                    raise StorageError("NFS host is unreachable", "host-unreachable")
                if any(marker in diagnostics for marker in ("not exported", "no such file", "access denied by server")):
                    raise StorageError("NFS export was not found", "resource-not-found")
            if argv and argv[0] == "umount" and any(marker in diagnostics for marker in ("target is busy", "device or resource busy")):
                raise StorageError("storage target is busy", "target-busy")
            raise StorageError("mount command failed")

    @staticmethod
    def _read_mountinfo() -> str:
        return Path("/proc/self/mountinfo").read_text(encoding="ascii")

    @staticmethod
    def _unescape_mountinfo(value: str) -> str:
        return re.sub(r"\\\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)

    def _mounted_entry(self, root: Path) -> tuple[str, str] | None:
        canonical = str(root.resolve(strict=True))
        for line in self.mountinfo().splitlines():
            fields = line.split()
            try:
                separator = fields.index("-")
                mountpoint, filesystem, source = fields[4], fields[separator + 1], fields[separator + 2]
            except (ValueError, IndexError):
                continue
            if self._unescape_mountinfo(mountpoint) == canonical:
                return filesystem, self._unescape_mountinfo(source)
        return None

    def _expected_mount(self, request: StorageRequest, root: Path) -> bool:
        entry = self._mounted_entry(root)
        if entry is None:
            return False
        filesystem, source = entry
        kind = request.location.kind
        expected_types = {
            StorageKind.SMB: {"cifs"}, StorageKind.NFS: {"nfs", "nfs4"},
            StorageKind.SSH: {"fuse.sshfs"},
        }
        if kind in expected_types:
            return source == self._source(request.location) and filesystem in expected_types[kind]
        # Block sources must remain local filesystems, never a substituted network mount.
        return source == self._source(request.location) and filesystem not in {"cifs", "nfs", "nfs4", "fuse.sshfs"}

    def _credentials(self, request: StorageRequest) -> str | None:
        if not request.credentials:
            return None
        fd, path = tempfile.mkstemp(prefix="credentials-", dir=self.runtime, text=True)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                for key in sorted(request.credentials):
                    stream.write(f"{key}={request.credentials[key]}\n")
        except BaseException:
            os.close(fd)
            os.unlink(path)
            raise
        return path

    def _mount_argv(self, request: StorageRequest, root: Path, credentials: str | None) -> tuple[str, ...]:
        source = self._source(request.location)
        if request.location.kind is StorageKind.SMB:
            options = ["nosuid", "nodev", "noexec", f"uid={self.caller_uid}", f"gid={self.caller_gid}"]
            if request.read_only:
                options.append("ro")
            if credentials:
                options.append(f"credentials={credentials}")
            return ("mount", "-t", "cifs", source, str(root), "-o", ",".join(options))
        if request.location.kind is StorageKind.NFS:
            options = ["nosuid", "nodev", "noexec"] + (["ro"] if request.read_only else [])
            return ("mount", "-t", "nfs", source, str(root), "-o", ",".join(options))
        if request.location.kind is StorageKind.SSH:
            if not self._fuse_allows_other():
                raise StorageError("sshfs allow_other is unavailable")
            options = ["StrictHostKeyChecking=yes", f"UserKnownHostsFile={self._known_hosts()}", "nosuid", "nodev",
                         "noexec", "reconnect", "allow_other", "default_permissions"]
            method = request.credentials.get("auth_method", "password")
            if method == "password":
                options.append("password_stdin")
            elif method == "private-key":
                options.extend((f"IdentityFile={self._identity_file(request)}", "IdentitiesOnly=yes", "BatchMode=yes"))
            elif method == "agent":
                options.extend((f"IdentityAgent={self._agent_socket(request)}", "BatchMode=yes"))
            else:
                raise StorageError("invalid SSH authentication method")
            if request.read_only:
                options.append("ro")
            argv = ["sshfs"]
            if request.location.port:
                argv.extend(("-p", str(request.location.port)))
            argv.extend((source, str(root), "-o", ",".join(options)))
            return tuple(argv)
        options = ["nosuid", "nodev", "noexec"] + (["ro"] if request.read_only else [])
        return ("mount", source, str(root), "-o", ",".join(options))

    def _fuse_allows_other(self) -> bool:
        try:
            info = self.fuse_conf.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
                return False
            return any(line.strip() == "user_allow_other" for line in self.fuse_conf.read_text(encoding="ascii").splitlines())
        except OSError:
            return False

    def _known_hosts(self) -> Path:
        """Return the runner-owned strict host-key database after rejecting replacements."""
        try:
            self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
            state_info = self.state.lstat()
        except OSError as exc:
            raise StorageError("known hosts state is unavailable") from exc
        expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
        if (stat.S_ISLNK(state_info.st_mode) or not stat.S_ISDIR(state_info.st_mode)
                or state_info.st_uid != expected_owner or stat.S_IMODE(state_info.st_mode) != 0o700):
            raise StorageError("invalid known hosts state")
        path = self.state / f"known_hosts-{self.caller_uid}"
        try:
            info = path.lstat()
        except FileNotFoundError:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != expected_owner or stat.S_IMODE(info.st_mode) != 0o600):
            raise StorageError("invalid known hosts file")
        return path

    def _known_host_present(self, path: Path, token: str) -> bool:
        try:
            for line in path.read_text(encoding="ascii").splitlines():
                try:
                    parse_ssh_host_key(line, token)
                    return True
                except ValueError:
                    pass
        except OSError as exc:
            raise StorageError("known hosts file is unavailable") from exc
        return False

    def _approve_host_key(self, request: StorageRequest) -> None:
        if request.location.kind is not StorageKind.SSH:
            return
        path = self._known_hosts()
        token = normalized_known_host_token(request.location.host or "", request.location.port)
        approved = request.credentials.get("host_key")
        if approved is None:
            if not self._known_host_present(path, token):
                raise StorageError("SSH host key is not approved")
            return
        parse_ssh_host_key(approved, token)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            data = os.read(fd, 1_048_576).decode("ascii")
            lines = data.splitlines()
            existing = []
            for line in lines:
                try:
                    existing.append((line, parse_ssh_host_key(line, token)))
                except ValueError:
                    continue
            approved_key = parse_ssh_host_key(approved, token)
            if existing and all(key != approved_key for _line, key in existing):
                raise StorageError("SSH host key changed", "host-key-changed")
            if not existing:
                os.lseek(fd, 0, os.SEEK_END)
                os.write(fd, (approved + "\n").encode("ascii"))
                os.fsync(fd)
        finally:
            os.close(fd)

    def _identity_file(self, request: StorageRequest) -> Path:
        value = request.credentials.get("identity_file", "")
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise StorageError("invalid SSH identity file")
        try:
            info = path.lstat()
        except OSError as exc:
            raise StorageError("SSH identity file is unavailable") from exc
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.caller_uid or stat.S_IMODE(info.st_mode) & 0o077):
            raise StorageError("invalid SSH identity file")
        return path

    def _agent_socket(self, request: StorageRequest) -> Path:
        value = request.credentials.get("agent_socket", "")
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise StorageError("invalid SSH agent socket")
        try:
            info = path.lstat()
            parent = path.parent.lstat()
        except OSError as exc:
            raise StorageError("SSH agent is unavailable") from exc
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.caller_uid
                or stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != self.caller_uid or stat.S_IMODE(parent.st_mode) & 0o077):
            raise StorageError("invalid SSH agent socket")
        return path

    def _write_marker(self, request: StorageRequest, root: Path) -> None:
        import json
        marker = self.base / f"{request.request_id}.marker"
        data = json.dumps({"request_id": request.request_id, "kind": request.location.kind.value,
                           "source": self._source(request.location), "root": str(root),
                           "uid": self.caller_uid, "gid": self.caller_gid},
                          ensure_ascii=True, separators=(",", ":")).encode("ascii")
        fd, temporary = tempfile.mkstemp(prefix=".marker-", dir=self.base)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
            os.close(fd)
            os.replace(temporary, marker)
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

    def _mount(self, request: StorageRequest) -> StorageResult:
        if request.location.kind not in {StorageKind.SMB, StorageKind.NFS, StorageKind.SSH, StorageKind.BLOCK_DEVICE, StorageKind.REMOVABLE}:
            raise StorageError("unsupported storage kind")
        if request.location.kind is StorageKind.SSH and self.which("sshfs", path="/usr/sbin:/usr/bin:/sbin:/bin") is None:
            raise StorageError("sshfs is unavailable")
        self._prepare_base()
        root = self._root(request)
        marker = self.base / f"{request.request_id}.marker"
        if root.exists() or root.is_symlink() or marker.exists() or marker.is_symlink():
            raise StorageError("mount request already exists")
        root.mkdir(mode=0o700)
        os.chown(root, self.caller_uid, self.caller_gid)
        credentials = None
        try:
            self._approve_host_key(request)
            # sshfs reads its password directly from stdin; never materialize it on disk.
            credentials = self._credentials(request) if request.location.kind is StorageKind.SMB else None
            password = request.credentials.get("password") if request.location.kind is StorageKind.SSH else None
            self._run(self._mount_argv(request, root, credentials),
                      (password + "\n").encode("utf-8") if password is not None else None)
            if not self.is_mount(str(root)):
                raise StorageError("mount not present")
            self._write_marker(request, root)
        except BaseException:
            if self.is_mount(str(root)):
                try:
                    self._run(("umount", "--", str(root)))
                except Exception:
                    pass
            root.rmdir()
            raise
        finally:
            if credentials:
                try:
                    os.unlink(credentials)
                except FileNotFoundError:
                    pass
        return StorageResult(request.request_id, "ok", str(root), "mounted")

    def _unmount(self, request: StorageRequest) -> StorageResult:
        self._prepare_base()
        root = self._root(request)
        marker = self.base / f"{request.request_id}.marker"
        if not marker.is_file() or marker.is_symlink():
            return StorageResult(request.request_id, "not-mounted", None, "not mounted")
        marker_info = marker.stat()
        owner = 0 if os.geteuid() == 0 else os.geteuid()
        if (marker_info.st_uid != owner or stat.S_IMODE(marker_info.st_mode) != 0o600
                or not stat.S_ISREG(marker_info.st_mode) or root.is_symlink()
                or root.parent.resolve(strict=True) != self.base.resolve(strict=True)):
            raise StorageError("mount ownership is invalid")
        import json
        try:
            data = json.loads(marker.read_text(encoding="ascii"))
        except (OSError, ValueError):
            raise StorageError("invalid mount marker")
        if data != {"request_id": request.request_id, "kind": request.location.kind.value,
                    "source": self._source(request.location), "root": str(root),
                    "uid": self.caller_uid, "gid": self.caller_gid}:
            raise StorageError("mount marker does not match request")
        entry = self._mounted_entry(root)
        if entry is None:
            marker.unlink()
            root.rmdir()
            return StorageResult(request.request_id, "not-mounted", None, "not mounted")
        if not self._expected_mount(request, root):
            raise StorageError("mounted filesystem does not match request", "protocol-mismatch")
        self._run(("umount", "--", str(root)))
        if self.is_mount(str(root)):
            raise StorageError("unmount not complete")
        marker.unlink()
        root.rmdir()
        return StorageResult(request.request_id, "ok", None, "unmounted")


class RunnerStorageExecutor:
    """Production adapter kept separate from the legacy argv executor used by tests."""

    def __call__(self, request: StorageRequest) -> StorageResult:
        from .client import run_storage_request
        return run_storage_request(request)


_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
_SHARE = re.compile(r"[^/\\\x00]{1,128}\Z")
_USERNAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")


def _canonical_path(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty absolute path")
    if "\x00" in value:
        raise ValueError(f"{name} contains NUL")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be absolute")
    if ".." in path.parts:
        raise ValueError(f"{name} contains path traversal")
    return "/" + os.path.normpath(str(path)).lstrip("/")


def _canonical_endpoint(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("endpoint must be a non-empty absolute path")
    if "\x00" in value:
        raise ValueError("endpoint contains NUL")
    path = PurePosixPath(value)
    if not path.is_absolute():
        raise ValueError("endpoint must be absolute")
    if ".." in path.parts:
        raise ValueError("endpoint contains path traversal")
    return "/" + str(path).lstrip("/")


def prepare_smb_subfolder(root: Path, endpoint: str) -> Path:
    """Create an SMB subfolder without following links outside the mounted share."""
    mount_root = root.resolve(strict=True)
    if not mount_root.is_dir():
        raise ValueError("SMB mount root must be a directory")
    current = mount_root
    for component in PurePosixPath(_canonical_endpoint(endpoint)).parts[1:]:
        candidate = current / component
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            candidate.mkdir()
        else:
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("SMB subfolder must not contain symbolic links")
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("SMB subfolder must be a directory")
        current = candidate
    return current


def _validate_host(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid host")
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        if not _HOST.fullmatch(value):
            raise ValueError("invalid host")


@dataclass(frozen=True, slots=True)
class StorageLocation:
    """A credential-free, validated description of a storage location."""

    kind: StorageKind
    root: str
    host: str | None = None
    endpoint: str | None = None
    share: str | None = None
    device: str | None = None
    username: str | None = None
    port: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", _canonical_path(self.root, "root"))
        network = {StorageKind.SMB, StorageKind.NFS, StorageKind.SSH}
        if self.kind in network:
            if self.device is not None:
                raise ValueError("network location cannot have a device")
            _validate_host(self.host or "")
            object.__setattr__(self, "endpoint", _canonical_endpoint(self.endpoint or ""))
            if self.kind is StorageKind.SMB:
                if not self.share or not _SHARE.fullmatch(self.share):
                    raise ValueError("SMB location requires a valid share")
            elif self.share is not None:
                raise ValueError("only SMB locations may have a share")
            if self.kind is StorageKind.SSH:
                if not self.username or not _USERNAME.fullmatch(self.username):
                    raise ValueError("SSH location requires a valid username")
            elif self.username is not None:
                raise ValueError("only SSH locations may have a username")
            if self.port is not None and (isinstance(self.port, bool) or not 1 <= self.port <= 65535):
                raise ValueError("invalid port")
            return
        if any(value is not None for value in (self.host, self.endpoint, self.share, self.username, self.port)):
            raise ValueError("local location cannot have network fields")
        if self.kind in {StorageKind.BLOCK_DEVICE, StorageKind.REMOVABLE}:
            if (not self.device or "\x00" in self.device or ".." in Path(self.device).parts
                    or not self.device.startswith("/dev/")):
                raise ValueError("device location requires a /dev device")
            object.__setattr__(self, "device", os.path.normpath(self.device))
        elif self.device is not None:
            raise ValueError("location cannot have a device")


@dataclass(slots=True)
class MountSession:
    location: StorageLocation
    ownership: MountOwnership
    state: ConnectionState = ConnectionState.DISCONNECTED
    error: str | None = None
    request_id: str | None = None
    effective_location: StorageLocation | None = None

    def transition(self, target: ConnectionState) -> None:
        allowed = {
            ConnectionState.DISCONNECTED: {ConnectionState.CONNECTING},
            ConnectionState.CONNECTING: {ConnectionState.MOUNTED, ConnectionState.FAILED},
            ConnectionState.MOUNTED: {ConnectionState.UNMOUNTING},
            ConnectionState.UNMOUNTING: {ConnectionState.DISCONNECTED, ConnectionState.FAILED},
            ConnectionState.FAILED: {ConnectionState.DISCONNECTED, ConnectionState.CONNECTING},
        }
        if target not in allowed[self.state]:
            raise StorageError(f"cannot transition {self.state} to {target}")
        self.state = target
        self.error = None

    def fail(self, message: str) -> None:
        if self.state not in {ConnectionState.CONNECTING, ConnectionState.UNMOUNTING}:
            raise StorageError(f"cannot fail session in {self.state}")
        self.state = ConnectionState.FAILED
        self.error = message


CommandExecutor = Callable[[Sequence[str]], object]


@dataclass(slots=True)
class StorageManager:
    executor: CommandExecutor | None = None
    storage_executor: Callable[[StorageRequest], StorageResult] | None = None
    sessions: list[MountSession] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.executor is None and self.storage_executor is None:
            self.storage_executor = RunnerStorageExecutor()

    def register_existing_local_folder(self, root: str) -> MountSession:
        location = StorageLocation(StorageKind.LOCAL_FOLDER, root)
        session = MountSession(location, MountOwnership.EXTERNAL, ConnectionState.MOUNTED)
        self.sessions.append(session)
        return session

    def register(self, location: StorageLocation, ownership: MountOwnership = MountOwnership.TRANSUME) -> MountSession:
        session = MountSession(location, ownership)
        self.sessions.append(session)
        return session

    def mount(self, session: MountSession, credentials: Mapping[str, str] | None = None) -> None:
        if session.ownership is MountOwnership.EXTERNAL:
            raise StorageError("cannot mount an external session")
        session.transition(ConnectionState.CONNECTING)
        credential_path: str | None = None
        try:
            if self.storage_executor is not None:
                request = StorageRequest(session.request_id or uuid4().hex, "mount", session.location,
                                         credentials or {})
                # Retain the one-shot identity even if the client loses the result frame;
                # cleanup can then recover a mount that the runner already created.
                session.request_id = request.request_id
                result = self.storage_executor(request)
                if result.status != "ok" or result.root is None:
                    raise StorageError(result.detail or "privileged mount failed",
                                       result.error_code or "operation-failed")
                session.location = replace(session.location, root=result.root)
                session.transition(ConnectionState.MOUNTED)
                return
            if credentials is not None:
                credential_path = self._write_credentials(credentials)
            self._execute(self._mount_argv(session.location, credential_path))
        except Exception as exc:
            message = str(exc) or exc.__class__.__name__
            session.fail(f"mount failed: {message}")
            raise StorageError(session.error,
                               getattr(exc, "code", "operation-failed")) from exc
        finally:
            if credential_path:
                self._remove_credentials(credential_path)
        session.transition(ConnectionState.MOUNTED)

    def unmount(self, session: MountSession) -> None:
        if session.ownership is MountOwnership.EXTERNAL:
            raise StorageError("cannot unmount an external session")
        # A failed unmount may still have a live mount. Keep the same request/session
        # available for an explicit retry rather than adopting or replacing it.
        if session.state is ConnectionState.FAILED:
            session.state = ConnectionState.MOUNTED
            session.error = None
        session.transition(ConnectionState.UNMOUNTING)
        try:
            if self.storage_executor is not None:
                if session.request_id is None:
                    raise StorageError("missing privileged mount request")
                result = self.storage_executor(StorageRequest(session.request_id, "unmount", session.location))
                if result.status not in {"ok", "not-mounted"}:
                    raise StorageError(result.detail or "privileged unmount failed",
                                       result.error_code or "operation-failed")
                session.transition(ConnectionState.DISCONNECTED)
                return
            self._execute(("umount", "--", session.location.root))
        except Exception as exc:
            session.fail(f"unmount failed: {str(exc) or exc.__class__.__name__}")
            raise StorageError(session.error,
                               getattr(exc, "code", "operation-failed")) from exc
        session.transition(ConnectionState.DISCONNECTED)

    def cleanup_owned(self) -> tuple[str, ...]:
        errors = []
        for session in self.sessions:
            if session.ownership is MountOwnership.TRANSUME and session.state in {ConnectionState.MOUNTED, ConnectionState.FAILED}:
                try:
                    self.unmount(session)
                except StorageError as exc:
                    errors.append(str(exc))
        return tuple(errors)

    def _execute(self, argv: Sequence[str]) -> None:
        if self.executor is None:
            raise StorageError("no command executor")
        result = self.executor(tuple(argv))
        if isinstance(result, int) and result != 0:
            raise StorageError(f"command exited with status {result}")
        returncode = getattr(result, "returncode", 0)
        if returncode != 0:
            raise StorageError(f"command exited with status {returncode}")

    @staticmethod
    def _mount_argv(location: StorageLocation, credentials: str | None) -> tuple[str, ...]:
        if location.kind is StorageKind.SMB:
            assert location.host and location.share and location.endpoint
            options = [f"credentials={credentials}"] if credentials else []
            return ("mount", "-t", "cifs", f"//{location.host}/{location.share}", location.root, *( ("-o", ",".join(options)) if options else ()))
        if location.kind is StorageKind.NFS:
            assert location.host and location.endpoint
            return ("mount", "-t", "nfs", f"{location.host}:{location.endpoint}", location.root)
        if location.kind is StorageKind.SSH:
            assert location.host and location.endpoint and location.username
            source = f"{location.username}@{location.host}:{location.endpoint}"
            if location.port:
                return ("sshfs", "-p", str(location.port), source, location.root)
            return ("sshfs", source, location.root)
        if location.kind in {StorageKind.BLOCK_DEVICE, StorageKind.REMOVABLE}:
            assert location.device
            return ("mount", location.device, location.root)
        raise StorageError("location kind does not require mounting")

    @staticmethod
    def _write_credentials(credentials: Mapping[str, str]) -> str:
        if not credentials or any(
            not isinstance(key, str) or not isinstance(value, str)
            or any(character in key or character in value for character in "\x00\r\n")
            for key, value in credentials.items()
        ):
            raise ValueError("credentials must be non-empty text values")
        fd, path = tempfile.mkstemp(prefix="transume-", text=True)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                fd = -1
                for key in sorted(credentials):
                    stream.write(f"{key}={credentials[key]}\n")
        except BaseException:
            if fd != -1:
                os.close(fd)
            os.unlink(path)
            raise
        return path

    @staticmethod
    def _remove_credentials(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
