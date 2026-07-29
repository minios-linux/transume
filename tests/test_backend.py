import io
import json
import json
import os
import stat
import socket
import subprocess
import threading

import pytest

from transume.capabilities import probe_clonezilla
from transume import client
from transume.client import SecretValue, policy_action, run_spec
from transume.clonezilla import OCS_CHKIMG, OCS_ONTHEFLY, OCS_SR, build_command
from transume.domain import DeviceIdentity, JobOperation, PublicJobSpec
from transume.inventory import parse_lsblk_json
from transume.protocol import PROTOCOL_VERSION, decode_frame, encode_message, read_message, redact_text, write_message
from transume.runner import (Command, RepositoryScopeManager, ResourceJournal, RunnerValidationError,
                                _acquire_lock, _enter_private_mount_namespace, _lock_is_stale,
                                _run_streaming, recover_resource_journals, run_job)


def device(path="/dev/sda", serial="SERIAL1234", device_type="disk"):
    name = path.rsplit("/", 1)[1]
    return DeviceIdentity(path, f"/sys/class/block/{name}", "8:0", device_type, 1000, serial=serial)


def spec(operation=JobOperation.SAVEDISK, **changes):
    values = dict(job_id="job-1", operation=operation, sources=(device(),),
                  repository="/images", image_name="backup", risk="write-image")
    values.update(changes)
    return PublicJobSpec(**values)


def test_domain_is_immutable_strict_and_redactable():
    job = spec()
    with pytest.raises(TypeError):
        job.options["x"] = True
    assert job.to_dict(redacted=True)["sources"][0]["serial"] == "***1234"
    assert PublicJobSpec.from_dict(job.to_dict()) == job
    with pytest.raises(ValueError):
        spec(options={"password": "bad"})


def test_inventory_propagates_mounted_system_and_live_safety():
    payload = {"blockdevices": [{"name": "sda", "type": "disk", "size": 100,
        "children": [{"name": "sda1", "type": "part", "size": 100,
                      "mountpoints": ["/"], "fstype": "ext4"}]},
        {"name": "sdb", "type": "disk", "size": "200", "ro": 0, "rm": 1}]}
    system, safe = parse_lsblk_json(json.dumps(payload))
    assert system.is_system and system.is_mounted and not system.selectable_destination
    assert safe.selectable_source and safe.selectable_destination
    live = parse_lsblk_json(json.dumps({"blockdevices": [{"name": "loop0", "type": "loop", "size": 1, "fstype": "squashfs"}]}))[0]
    assert live.is_live and not live.selectable_source


def test_capability_probe_is_conservative_and_parses_version():
    present = {"ocs-sr": "/usr/sbin/ocs-sr", "zstd": "/usr/bin/zstd"}
    caps = probe_clonezilla(which=present.get, run=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "Clonezilla 3.1.2-8", ""))
    assert caps.version == "3.1.2-8"
    assert caps.supports("savedisk") and caps.compressors == frozenset({"zstd"})
    assert not caps.supports("clone-disk")


def test_capability_probe_accepts_debian_partclone_variants():
    present = {
        "ocs-sr": "/usr/sbin/ocs-sr",
        "partclone.ext4": "/usr/sbin/partclone.ext4",
    }
    caps = probe_clonezilla(
        which=present.get,
        run=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "3.1.2", ""),
    )
    assert caps.supports("partclone")


def test_newer_clonezilla_keeps_feature_detected_ecryptfs_support():
    present = {
        "ocs-sr": "/usr/sbin/ocs-sr",
        "mount.ecryptfs": "/usr/bin/mount.ecryptfs",
        "ecryptfs-add-passphrase": "/usr/bin/ecryptfs-add-passphrase",
    }
    caps = probe_clonezilla(
        which=present.get,
        run=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "6.0.0-1", ""),
    )
    assert caps.version == "6.0.0-1"
    assert caps.supports("ecryptfs")


@pytest.mark.parametrize(("operation", "expected"), [
    (JobOperation.SAVEDISK, OCS_SR), (JobOperation.SAVEPARTS, OCS_SR),
    (JobOperation.RESTOREDISK, OCS_SR), (JobOperation.RESTOREPARTS, OCS_SR),
    (JobOperation.CHECK_IMAGE, OCS_CHKIMG),
    (JobOperation.CLONE_DISK, OCS_ONTHEFLY), (JobOperation.CLONE_PART, OCS_ONTHEFLY)])
def test_typed_commands(operation, expected):
    if operation.value.startswith("save"):
        job = spec(operation)
    elif operation.value.startswith("restore"):
        job = spec(operation, sources=(), destinations=(device("/dev/sdb", "DEST5678"),), risk="destructive")
    elif operation is JobOperation.CHECK_IMAGE:
        job = spec(operation, sources=(), risk="read-only")
    else:
        job = spec(operation, destinations=(device("/dev/sdb", "DEST5678"),), repository=None, image_name=None, risk="destructive")
    command = build_command(job)
    assert command.argv[0] == expected
    assert all(isinstance(arg, str) for arg in command.argv)
    if operation in {JobOperation.CLONE_DISK, JobOperation.CLONE_PART}:
        assert "-d" in command.argv
        assert "-t" not in command.argv


def test_command_rejects_injection_and_same_clone_target():
    with pytest.raises(ValueError):
        build_command(spec(image_name="bad;name"))
    with pytest.raises(ValueError):
        build_command(spec(JobOperation.CLONE_DISK, destinations=(device(),), repository=None, image_name=None))


def test_save_options_are_typed_and_repository_is_explicit():
    command = build_command(spec(options={
        "compression": "zstd", "engine": "partclone", "rescue": True,
        "verify_image": True, "image_size": 4096,
    }))
    assert command.argv[:6] == (OCS_SR, "-batch", "-nogui", "-or", "/images", "-z9p")
    assert "-q2" in command.argv and "-rescue" in command.argv
    assert "-sc" not in command.argv
    with pytest.raises(ValueError):
        build_command(spec(options={"compression": "$(bad)"}))


def test_lzma_backup_uses_clonezilla_z4():
    command = build_command(spec(options={"compression": "lzma"}))
    assert "-z4" in command.argv


def test_restore_defaults_do_not_silently_resize_or_rewrite_geometry():
    job = spec(JobOperation.RESTOREDISK, sources=(),
               destinations=(device("/dev/sdb", "DEST5678"),), risk="destructive")
    command = build_command(job)
    assert "-r" not in command.argv
    assert "-e1" not in command.argv
    assert "-e2" not in command.argv
    assert command.argv[3:5] == ("-or", "/images")


def test_restore_options_map_inverted_safety_flags():
    job = spec(JobOperation.RESTOREDISK, sources=(),
               destinations=(device("/dev/sdb", "DEST5678"),), risk="destructive",
               options={"partition_table": "proportional", "resize": True,
                        "check_image": False, "restore_mbr": False})
    command = build_command(job)
    assert all(flag in command.argv for flag in ("-k1", "-r", "-scr", "-t"))


def test_restoreparts_source_partition_maps_with_clonezilla_f():
    job = spec(
        JobOperation.RESTOREPARTS, sources=(),
        destinations=(device("/dev/sdb1", "DEST5678", device_type="part"),),
        risk="destructive", options={"source_partition": "sda2"},
    )

    command = build_command(job)

    assert command.argv[command.argv.index("-f") + 1] == "sda2"
    assert command.argv.index("-f") < command.argv.index("restoreparts")
    assert all(flag in command.argv for flag in ("-k", "-t", "-t2", "-iefi"))


def test_source_partition_rejects_disk_restore_and_multiple_targets():
    with pytest.raises(ValueError, match="source_partition"):
        build_command(spec(
            JobOperation.RESTOREDISK, sources=(),
            destinations=(device("/dev/sdb", "DEST5678"),), risk="destructive",
            options={"source_partition": "sda1"},
        ))


def test_restoreparts_rejects_disk_wide_metadata_options():
    with pytest.raises(ValueError, match="disk-wide metadata"):
        build_command(spec(
            JobOperation.RESTOREPARTS, sources=(),
            destinations=(device("/dev/sdb1", "ONE", device_type="part"),),
            risk="destructive", options={"partition_table": "original"},
        ))
    with pytest.raises(ValueError, match="source_partition"):
        build_command(spec(
            JobOperation.RESTOREPARTS, sources=(),
            destinations=(device("/dev/sdb1", "ONE", device_type="part"),
                          device("/dev/sdb2", "TWO", device_type="part")),
            risk="destructive", options={"source_partition": "sda1"},
        ))


def test_all_retained_editor_options_affect_clonezilla_argv():
    backup = build_command(spec(options={"compression": "gzip", "engine": "partclone",
                                         "verify_image": False, "rescue": True}))
    assert all(flag in backup.argv for flag in ("-z1p", "-q2", "-sc", "-rescue"))
    restore = build_command(spec(JobOperation.RESTOREDISK, sources=(),
                                 destinations=(device("/dev/sdb", "DEST5678"),), risk="destructive",
                                 options={"partition_table": "proportional", "resize": True,
                                          "check_image": False, "restore_mbr": False}))
    assert all(flag in restore.argv for flag in ("-k1", "-r", "-scr", "-t"))
    clone = build_command(spec(JobOperation.CLONE_DISK, destinations=(device("/dev/sdb", "DEST5678"),),
                               repository=None, image_name=None, risk="destructive",
                               options={"resize": True, "rescue": True, "force_dd": True,
                                        "hidden_data": True}))
    assert all(flag in clone.argv for flag in ("-r", "-rescue", "-q1", "-j2"))


def test_complete_backup_restore_clone_options_and_post_actions_map_exactly():
    backup = build_command(spec(options={"compression": "none", "engine": "dd", "rescue": True,
                                         "verify_image": False, "filesystem_check": "repair", "checksum": "files",
                                         "image_size": 64, "encrypt": True}, post_action="poweroff"))
    assert all(flag in backup.argv for flag in ("-z0", "-q1", "-rescue", "-sc", "-fsck-y", "-gmf", "-i", "64", "-enc", "-p", "poweroff"))
    restore = build_command(spec(JobOperation.RESTOREDISK, sources=(), destinations=(device("/dev/sdb", "DEST"),),
                                 risk="destructive", post_action="reboot", options={"partition_table": "existing", "check_image": False,
                                 "resize": True, "restore_mbr": False, "restore_ebr": False, "hidden_data": True,
                                  "update_efi": False, "encrypted": True}))
    assert all(flag in restore.argv for flag in ("-k", "-scr", "-r", "-t", "-t2", "-j2", "-iefi", "-enc", "-p", "reboot"))
    clone = build_command(spec(JobOperation.CLONE_DISK, destinations=(device("/dev/sdb", "DEST"),), repository=None,
                               image_name=None, risk="destructive", post_action="none", options={"direct_io": True}))
    assert "--postaction" in clone.argv and clone.argv[clone.argv.index("--postaction") + 1] == "true" and "-edio" in clone.argv


def test_encrypted_backup_requires_secret_and_cleans_up(tmp_path):
    job = spec(options={"encrypt": True})
    with pytest.raises(RunnerValidationError, match="encryption secret"):
        run_job(job, authorized=True, resolve_identity=lambda item: item, execute=lambda *_args, **_kwargs: None)
    captured = {}
    value = bytearray(b"private")
    def execute(argv, **kwargs):
        captured["path"] = argv[argv.index("-pfe") + 1]
        assert "-enc" in argv and "-goc" not in argv
        assert open(captured["path"], "rb").read() == b"passphrase_passwd=private\n"
        assert stat.S_IMODE(os.stat(captured["path"]).st_mode) == 0o600
        assert "passwd_file_gocryptfs" not in kwargs["env"]
        return subprocess.CompletedProcess(argv, 0, b"private", b"private")
    result = run_job(job, authorized=True, resolve_identity=lambda item: item, execute=execute,
                     passphrase=value, runtime_dir=tmp_path)
    assert result.stdout == result.stderr == "***"
    assert not value and not os.path.exists(captured["path"])


def test_encrypted_restore_injects_private_passphrase_file(tmp_path):
    job = spec(JobOperation.RESTOREDISK, sources=(), destinations=(device("/dev/sdb", "DEST"),),
               risk="destructive", options={"encrypted": True})
    captured = {}
    value = bytearray(b"private")

    def execute(argv, **_kwargs):
        captured["argv"] = argv
        captured["path"] = argv[argv.index("-pfe") + 1]
        assert open(captured["path"], "rb").read() == b"passphrase_passwd=private\n"
        return subprocess.CompletedProcess(argv, 0)

    result = run_job(job, authorized=True, resolve_identity=lambda item: item, execute=execute,
                     passphrase=value, runtime_dir=tmp_path)
    assert "-enc" in captured["argv"] and captured["argv"].index("-pfe") < captured["argv"].index("restoredisk")
    assert not value and not os.path.exists(captured["path"]) and result.returncode == 0


def test_repository_scope_uses_runner_pid_and_reports_cleanup_after_exit(tmp_path):
    calls = []

    def execute(argv, **_kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    repository = tmp_path / "repository"
    repository.mkdir()
    job = spec(repository=str(repository))
    manager = RepositoryScopeManager(tmp_path / "runtime", execute=execute)
    (tmp_path / "runtime/jobs").mkdir(parents=True, mode=0o700)
    manager._prepare_jobs_dir = lambda: None  # type: ignore[method-assign]  # Scope behavior is tested without root ownership.
    result = run_job(job, authorized=True, resolve_identity=lambda item: item,
                     execute=lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0),
                     scope_manager=manager)
    assert f"/proc/{os.getpid()}/fd/" in calls[0][2]
    assert calls[-1][:2] == ("/bin/umount", "--")
    assert result.cleanup == "complete"


def test_repository_scope_unmounts_when_command_raises(tmp_path):
    calls = []
    repository = tmp_path / "repository"
    repository.mkdir()
    manager = RepositoryScopeManager(tmp_path / "runtime", execute=lambda argv, **_kwargs: (calls.append(argv) or 0))
    (tmp_path / "runtime/jobs").mkdir(parents=True, mode=0o700)
    manager._prepare_jobs_dir = lambda: None  # type: ignore[method-assign]
    with pytest.raises(OSError, match="spawn"):
        run_job(spec(repository=str(repository)), authorized=True, resolve_identity=lambda item: item,
                execute=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("spawn")), scope_manager=manager)
    assert calls[-1][:2] == ("/bin/umount", "--")
    assert manager.cleanup_status == "complete"


def test_repository_scope_reuses_secure_jobs_parent(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    calls = []
    manager = RepositoryScopeManager(
        runtime,
        execute=lambda argv, **_kwargs: (calls.append(argv) or 0),
    )
    manager._prepare_jobs_dir = lambda: (runtime / "jobs").mkdir(mode=0o700, exist_ok=True)  # type: ignore[method-assign]
    first = type("Spec", (), {"repository": str(repository), "job_id": "first"})()
    second = type("Spec", (), {"repository": str(repository), "job_id": "second"})()

    with manager.scope(first):
        pass
    with manager.scope(second):
        pass

    assert len([argv for argv in calls if argv[:2] == ("/bin/mount", "--bind")]) == 2


def test_resource_journal_persists_bind_mount_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr("transume.runner._boot_id", lambda: "boot")
    monkeypatch.setattr("transume.runner._process_start_time", lambda _pid: "start")
    journal = ResourceJournal(tmp_path, "job-1")
    resource = tmp_path / "jobs" / "job-1"
    journal.record("bind-mount", resource, "prepared")
    journal.record("bind-mount", resource, "mounted")
    journal.complete(True)
    data = json.loads((tmp_path / "journals" / "job-1.json").read_text())
    assert data["state"] == "complete"
    assert data["resources"][-1] == {"kind": "bind-mount", "path": str(resource), "state": "mounted"}
    assert stat.S_IMODE((tmp_path / "journals" / "job-1.json").stat().st_mode) == 0o600


def test_stale_resource_journal_recovers_only_exact_job_path(tmp_path, monkeypatch):
    monkeypatch.setattr("transume.runner._boot_id", lambda: "new-boot")
    monkeypatch.setattr("transume.runner._process_start_time", lambda _pid: "new-start")
    journal = ResourceJournal(tmp_path, "stale-job")
    job = tmp_path / "jobs" / "stale-job"
    job.mkdir(parents=True)
    journal.record("bind-mount", job, "mounted")
    journal.data.update({"pid": 999999, "boot_id": "old-boot", "start_time": "old-start"})
    journal._write()

    recover_resource_journals(tmp_path)

    assert not job.exists()
    assert json.loads(journal.path.read_text())["state"] == "recovered"


def test_stale_resource_journal_rejects_unowned_path(tmp_path, monkeypatch):
    monkeypatch.setattr("transume.runner._boot_id", lambda: "new-boot")
    monkeypatch.setattr("transume.runner._process_start_time", lambda _pid: "new-start")
    journal = ResourceJournal(tmp_path, "stale-job")
    journal.data["resources"] = [{"kind": "bind-mount", "path": "/home", "state": "mounted"}]
    journal.data.update({"pid": 999999, "boot_id": "old-boot", "start_time": "old-start"})
    journal._write()

    with pytest.raises(RunnerValidationError, match="invalid resource journal resource"):
        recover_resource_journals(tmp_path)


def test_stale_lock_metadata_is_replaced_after_kernel_lock_recovery(tmp_path, monkeypatch):
    lock_path = tmp_path / "job.lock"
    lock_path.write_text(json.dumps({"pid": 999999, "start_time": "old", "boot_id": "old", "job_id": "old"}))
    monkeypatch.setattr("transume.runner._boot_id", lambda: "boot")
    monkeypatch.setattr("transume.runner._process_start_time", lambda pid: "start" if pid == os.getpid() else (_ for _ in ()).throw(RunnerValidationError("gone")))
    assert _lock_is_stale(json.loads(lock_path.read_text()))
    handle = _acquire_lock("job-1", path=lock_path)
    try:
        assert json.loads(lock_path.read_text()) == {"pid": os.getpid(), "start_time": "start", "boot_id": "boot", "job_id": "job-1"}
        with pytest.raises(RunnerValidationError, match="another privileged disk job"):
            _acquire_lock("job-2", path=lock_path)
    finally:
        handle.close()


def test_private_mount_namespace_is_made_private_before_runner_mounts(monkeypatch):
    calls = []
    monkeypatch.setattr("transume.runner.os.unshare", lambda flags: calls.append(("unshare", flags)))
    monkeypatch.setattr("transume.runner.subprocess.run", lambda argv, **_kwargs: (calls.append(argv) or subprocess.CompletedProcess(argv, 0)))
    _enter_private_mount_namespace()
    assert calls[0][0] == "unshare"
    assert calls[1] == ("/bin/mount", "--make-rprivate", "/")


def test_redaction_ignores_empty_secret_tokens():
    assert redact_text("visible", secrets=("",)) == "visible"


def test_protocol_round_trip_and_validation():
    message = {"type": "hello", "version": PROTOCOL_VERSION}
    frame = encode_message(message)
    assert decode_frame(frame) == message
    assert read_message(io.BytesIO(frame)) == message
    output = io.BytesIO()
    write_message(output, message)
    assert output.getvalue() == frame
    with pytest.raises(ValueError):
        encode_message({**message, "extra": True})
    with pytest.raises(ValueError):
        decode_frame(b"\x00\x00\x00\x02{}junk")
    progress = {"type": "progress", "version": PROTOCOL_VERSION,
                "kind": "progress", "message": "Copying", "percent": 42.5,
                "device": "sda1", "rate": "1 GiB/min"}
    assert decode_frame(encode_message(progress)) == progress
    cancel = {"type": "cancel", "version": PROTOCOL_VERSION}
    assert decode_frame(encode_message(cancel)) == cancel
    with pytest.raises(ValueError):
        encode_message({**cancel, "reason": "no"})
    secret = {"type": "secret", "version": PROTOCOL_VERSION, "value": "correct horse"}
    assert decode_frame(encode_message(secret)) == secret
    for value in ("", "a\nb", "a\rb", "a\x00b", "a" * 4097):
        with pytest.raises(ValueError):
            encode_message({**secret, "value": value})


def test_runner_result_fails_when_clonezilla_reports_error_with_zero_exit(tmp_path, monkeypatch):
    from transume import runner

    job = spec()
    output = io.BytesIO()
    messages = iter((
        {"type": "hello", "version": PROTOCOL_VERSION},
        {"type": "job", "version": PROTOCOL_VERSION, "spec": job.to_dict()},
    ))
    def read(_stream):
        try:
            return next(messages)
        except StopIteration:
            raise EOFError from None
    monkeypatch.setattr(runner, "read_message", read)
    monkeypatch.setattr(runner, "write_message", lambda _stream, message: output.write(encode_message(message)))
    monkeypatch.setattr(runner, "run_job", lambda _spec, **kwargs: (
        kwargs["on_output"]("Failed to save partition /dev/sda1"),
        runner.RunResult((OCS_SR,), 0, False, cleanup="complete"),
    )[1])
    monkeypatch.setattr(runner.sys, "stdin", type("Input", (), {"buffer": io.BytesIO()})())
    monkeypatch.setattr(runner.sys, "stdout", type("Output", (), {"buffer": io.BytesIO()})())
    monkeypatch.setattr(runner, "_acquire_lock", lambda _job_id: io.StringIO())
    monkeypatch.setattr(runner, "_enter_private_mount_namespace", lambda: None)
    class Journal:
        data = {"state": "running"}
        def complete(self, success):
            self.data["state"] = "complete" if success else "cleanup-failed"
    monkeypatch.setattr(runner, "ResourceJournal", lambda *_args, **_kwargs: Journal())
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)

    assert runner.serve_once(action="write", runtime_dir=tmp_path) == 1
    result = {"type": "result", "version": PROTOCOL_VERSION, "status": "failed",
               "detail": "failed", "error_code": "clonezilla-reported-error", "exit_code": 2,
               "verification": "failed", "cleanup": "complete"}
    assert decode_frame(encode_message(result)) == result
    with pytest.raises(ValueError):
        encode_message({**result, "exit_code": True})
    with pytest.raises(ValueError):
        encode_message({**result, "error_code": "Clonezilla Failed"})


def test_persistent_mount_requests_use_shared_mount_namespace(monkeypatch):
    from transume import runner
    from transume.image_explorer import ExplorerRequest, ExplorerResult

    request = ExplorerRequest("request1", "status", session_id="session1")
    messages = iter((
        {"type": "hello", "version": PROTOCOL_VERSION},
        {"type": "explorer-request", "version": PROTOCOL_VERSION,
         "request": request.to_dict()},
    ))
    monkeypatch.setattr(runner, "read_message", lambda _stream: next(messages))
    monkeypatch.setattr(runner, "write_message", lambda _stream, _message: None)
    monkeypatch.setattr(runner.sys, "stdin", type("Input", (), {"buffer": io.BytesIO()})())
    monkeypatch.setattr(runner.sys, "stdout", type("Output", (), {"buffer": io.BytesIO()})())
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        runner, "_enter_private_mount_namespace",
        lambda: (_ for _ in ()).throw(AssertionError("persistent mount was isolated")),
    )
    monkeypatch.setattr(
        runner, "run_explorer_request",
        lambda _request: ExplorerResult("request1", "ok", "mounted", "session1", "/run/mount"),
    )

    assert runner.serve_once(action="mount") == 0


def test_storage_runner_emits_exact_storage_result_schema(monkeypatch):
    from transume import runner
    from transume.storage import StorageKind, StorageLocation, StorageRequest, StorageResult

    request = StorageRequest(
        "request1", "mount",
        StorageLocation(StorageKind.SMB, "/pending", host="files.example",
                        share="images", endpoint="/"),
    )
    messages = iter((
        {"type": "hello", "version": PROTOCOL_VERSION},
        {"type": "storage-request", "version": PROTOCOL_VERSION,
         "request": request.to_dict()},
    ))
    output = []
    monkeypatch.setattr(runner, "read_message", lambda _stream: next(messages))
    monkeypatch.setattr(runner, "write_message", lambda _stream, message: output.append(message))
    monkeypatch.setattr(runner.sys, "stdin", type("Input", (), {"buffer": io.BytesIO()})())
    monkeypatch.setattr(runner.sys, "stdout", type("Output", (), {"buffer": io.BytesIO()})())
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        runner, "run_storage_request",
        lambda _request: StorageResult("request1", "ok", "/run/transume/mounts/request1", "mounted"),
    )

    assert runner.serve_once(action="mount") == 0
    assert output[-1] == {
            "type": "storage-result", "version": PROTOCOL_VERSION,
            "request_id": "request1", "status": "ok",
            "root": "/run/transume/mounts/request1", "detail": "mounted",
            "error_code": None,
        }
    assert decode_frame(encode_message(output[-1])) == output[-1]


def test_runner_main_reports_safe_validation_reason(monkeypatch):
    from transume import runner

    messages = []
    monkeypatch.setattr(
        runner, "serve_once",
        lambda **_kwargs: (_ for _ in ()).throw(
            runner.RunnerValidationError("insufficient repository space")
        ),
    )
    monkeypatch.setattr(runner, "write_message", lambda _stream, message: messages.append(message))

    assert runner.main(["write", "--stdio"]) == 2
    assert messages[0]["detail"] == "insufficient repository space"
    assert messages[0]["error_code"] == "validation-failed"


def test_runner_dry_run_validates_without_execution():
    target = device("/dev/sdb", "DEST5678")
    job = spec(JobOperation.CLONE_DISK, destinations=(target,), repository=None,
               image_name=None, risk="destructive")
    called = False
    def execute(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("must not execute")
    result = run_job(job, authorized=True, dry_run=True,
                     resolve_identity=lambda identity: identity, execute=execute)
    assert result.dry_run and not called
    with pytest.raises(RunnerValidationError):
        run_job(job, authorized=False, dry_run=True, resolve_identity=lambda x: x)
    with pytest.raises(RunnerValidationError):
        run_job(job, authorized=True, dry_run=True,
                resolve_identity=lambda x: device(x.path, "CHANGED"))


def test_runner_cancellation_before_spawn_does_not_execute():
    cancelled = threading.Event()
    cancelled.set()
    called = False

    def execute(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("must not execute")

    result = run_job(spec(), authorized=True, resolve_identity=lambda identity: identity,
                     cancel_event=cancelled, execute=execute)
    assert result.cancelled and not called


def test_streaming_runner_terminates_the_child_process_group(monkeypatch):
    cancelled = threading.Event()
    cancelled.set()
    signals = []

    class Process:
        pid = 123
        stdout = io.StringIO("copying\n")

        def poll(self):
            return None if not signals else -15

        def wait(self):
            return -15

    captured = {}

    def popen(*args, **kwargs):
        captured.update(kwargs)
        return Process()

    monkeypatch.setattr("transume.runner.os.killpg", lambda pid, sig: signals.append((pid, sig)))
    command = Command(("safe-command",), False, (("PATH", "/usr/bin"),))
    result = _run_streaming(command, lambda _line: None, cancel_event=cancelled, popen=popen)
    assert result.cancelled
    assert signals == [(123, __import__("signal").SIGTERM)]
    assert captured["shell"] is False and captured["start_new_session"] is True


def test_client_sends_one_cancel_frame_without_closing_stdin(monkeypatch):
    parent, child = socket.socketpair()
    input_stream = parent.makefile("rwb", buffering=0)
    output_stream = parent.makefile("rwb", buffering=0)
    cancel = threading.Event()
    received = []

    def runner():
        reader = child.makefile("rb", buffering=0)
        writer = child.makefile("wb", buffering=0)
        assert read_message(reader)["type"] == "hello"
        write_message(writer, {"type": "hello", "version": PROTOCOL_VERSION})
        assert read_message(reader)["type"] == "job"
        cancel.set()
        received.append(read_message(reader))
        write_message(writer, {"type": "result", "version": PROTOCOL_VERSION,
                                "status": "cancelled", "detail": "cancelled", "error_code": "cancelled", "exit_code": -15,
                                "verification": "not-run", "cleanup": "complete"})
        writer.close()
        reader.close()
        child.close()

    class Process:
        stdin = input_stream
        stdout = output_stream
        stderr = io.BytesIO()
        returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    monkeypatch.setattr(client.shutil, "which", lambda _name: "/usr/bin/pkexec")
    result = run_spec(spec(), cancel_event=cancel, popen=lambda *_args, **_kwargs: Process())
    thread.join(timeout=1)
    assert result.status == "cancelled"
    assert result.exit_code == -15
    assert result.error_code == "cancelled"
    assert received == [{"type": "cancel", "version": PROTOCOL_VERSION}]


def test_one_shot_runner_protocol_dry_run():
    result = run_spec(spec(), dry_run=True)
    assert result.status == "dry-run"
    assert result.detail.startswith(OCS_SR)
    assert "-or /images" in result.detail


def test_client_classifies_pkexec_denial_as_cancelled_authorization(monkeypatch):
    class Process:
        stdin = io.BytesIO()
        stdout = io.BytesIO()
        stderr = io.BytesIO(b"Error executing command as another user: Not authorized\nThis incident has been reported.\n")
        returncode = 127

        def poll(self):
            return self.returncode

    monkeypatch.setattr(client.shutil, "which", lambda _name: "/usr/bin/pkexec")
    with pytest.raises(client.AuthorizationError, match="authorization was cancelled or denied"):
        run_spec(spec(), popen=lambda *_args, **_kwargs: Process())
