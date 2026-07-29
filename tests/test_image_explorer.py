import os
import stat
from pathlib import Path

import pytest

from transume.image_explorer import (ExplorerRequest, ImageExplorer, ImageExplorerError,
                                       derive_partclone_payloads, explorer_support_reason)
from transume.images import (ImageCandidate, ImageStatus, ImageType, SourcePartition,
                               SourceTopology)
from transume.protocol import PROTOCOL_VERSION, decode_frame, encode_message


def request(**changes):
    value = dict(request_id="request1", operation="connect", repository="/images", image_name="image",
                 image_fingerprint="a" * 64, source_partition="sda1")
    value.update(changes)
    return ExplorerRequest(**value)


def candidate(*, compression=(), encrypted=False, status=ImageStatus.READY, payloads=("sda1.ext4-ptcl-img",)):
    return ImageCandidate("local", Path("/images/image"), "image", "image", ImageType.SAVEPARTS, (), ("sda1",),
                          SourceTopology(partitions=(SourcePartition("sda1", "sda"),)), payloads, 1, None, None,
                          compression, False, encrypted, (), status, ())


def test_request_is_strict_and_session_requests_carry_no_client_paths():
    assert ExplorerRequest.from_dict(request().to_dict()) == request()
    with pytest.raises(ValueError): request(image_name="../image")
    with pytest.raises(ValueError): request(operation="disconnect")
    assert ExplorerRequest("request1", "disconnect", session_id="session1").session_id == "session1"


def test_explorer_protocol_frames_are_strict_and_round_trip():
    message = {"type": "explorer-request", "version": PROTOCOL_VERSION,
               "request": request().to_dict()}
    assert decode_frame(encode_message(message))["request"] == request().to_dict()
    result = {"type": "explorer-result", "version": PROTOCOL_VERSION,
              "request_id": "request1", "status": "ok", "root": None,
              "detail": "mounted", "session_id": "session1", "mountpoint": "/run/user/1000/files"}
    assert decode_frame(encode_message(result)) == result


def test_payload_derivation_sorts_splits_and_rejects_symlinks_and_compression(tmp_path):
    for name in ("sda1.ext4-ptcl-img.002", "sda1.ext4-ptcl-img.001"):
        (tmp_path / name).write_bytes(b"x")
    payloads, compression = derive_partclone_payloads(tmp_path, "sda1")
    assert [path.name for path in payloads] == ["sda1.ext4-ptcl-img.001", "sda1.ext4-ptcl-img.002"]
    assert compression == "none"
    (tmp_path / "sda2.ext4-ptcl-img.zst").write_bytes(b"x")
    with pytest.raises(ImageExplorerError, match="unsupported"): derive_partclone_payloads(tmp_path, "sda2")
    (tmp_path / "sda4.ext4-ptcl-img.lzma").write_bytes(b"x")
    with pytest.raises(ImageExplorerError, match="unsupported"): derive_partclone_payloads(tmp_path, "sda4")
    (tmp_path / "sda3.ext4-ptcl-img").symlink_to(tmp_path / "sda1.ext4-ptcl-img.001")
    with pytest.raises(ImageExplorerError, match="regular"): derive_partclone_payloads(tmp_path, "sda3")


def test_ui_reason_is_visible_for_unsupported_formats():
    assert explorer_support_reason(candidate(compression=("zstd",))) == "Cannot explore zstd compression; supported formats are none, gzip, and xz"
    assert explorer_support_reason(candidate(encrypted=True, status=ImageStatus.ENCRYPTED)) == "Encrypted images cannot be explored"
    assert explorer_support_reason(candidate(payloads=("sda1.dd-img",))) == "Only Partclone payloads can be explored"


def test_fixed_command_argv_never_accepts_payload_commands(tmp_path):
    explorer = ImageExplorer(runtime=tmp_path, mount_runtime=tmp_path / "mounts")
    join = explorer._join_argv(tmp_path / "join.sock", (tmp_path / "a;bad",))
    decode = explorer._decode_argv(tmp_path / "decode.sock", "/dev/nbd0", "gzip")
    assert join[:7] == ("/usr/bin/nbdkit", "--foreground", "--readonly", "--unix", str(tmp_path / "join.sock"), "--filter=truncate", "split")
    assert decode[0] == "/usr/bin/nbdkit" and "file=/dev/nbd0" in decode


def test_actual_partclone_argv_and_compressed_pipeline_shape(tmp_path):
    explorer = ImageExplorer(runtime=tmp_path, mount_runtime=tmp_path / "mounts")
    assert ("/usr/bin/partclone-nbd", "-d", "/dev/nbd2", "-c", "/dev/nbd1") == (
        "/usr/bin/partclone-nbd", "-d", "/dev/nbd2", "-c", "/dev/nbd1"
    )
    assert explorer._decode_argv(tmp_path / "decode.sock", "/dev/nbd0", "xz")[-2:] == ("file=/dev/nbd0", "round-up=512")


def test_free_nbd_without_pid_is_claimed_once(tmp_path, monkeypatch):
    sys_block = tmp_path / "sys"; sys_block.mkdir()
    for name in ("nbd0", "nbd1", "nbd2"):
        (sys_block / name).mkdir()
        (sys_block / name / "size").write_text("0\n")
    original_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda path: str(path).startswith("/dev/nbd") or original_exists(path))
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts", sys_block=sys_block)
    state = {"nbds": []}
    monkeypatch.setattr(explorer, "_checkpoint", lambda _state: None)
    assert explorer._claim_nbd(state) == "/dev/nbd0"
    assert explorer._claim_nbd(state) == "/dev/nbd1"


def test_nonzero_size_nbd_is_not_claimed(tmp_path, monkeypatch):
    sys_block = tmp_path / "sys"; entry = sys_block / "nbd0"; entry.mkdir(parents=True)
    (entry / "size").write_text("1\n")
    original_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda path: str(path).startswith("/dev/nbd") or original_exists(path))
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts", sys_block=sys_block)
    monkeypatch.setattr(explorer, "_checkpoint", lambda _state: None)
    with pytest.raises(ImageExplorerError, match="no free NBD"): explorer._claim_nbd({"nbds": []})


def test_cleanup_never_detaches_claimed_but_unattached_nbd(tmp_path, monkeypatch):
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts")
    explorer._prepare(); session = "session1"; directory = explorer.runtime / session; directory.mkdir(); visible = explorer.mount_runtime / session; visible.mkdir()
    commands = []; monkeypatch.setattr(explorer, "_run", lambda argv, **_kwargs: commands.append(argv))
    monkeypatch.setattr(explorer, "is_mount", lambda _path: False)
    state = {"session_id": session, "caller_uid": explorer.uid, "caller_gid": explorer.gid,
             "directory": str(directory), "pinned": str(directory / "repository"),
             "mountpoint": str(visible / "files"), "pids": [], "nbds": ["/dev/nbd0"],
             "attached": [], "mounted": False}
    explorer._cleanup(state, False)
    assert not any(command[:2] == ("/usr/sbin/nbd-client", "-d") for command in commands)


def test_cleanup_detaches_nbd_before_terminating_backends(tmp_path, monkeypatch):
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts")
    explorer._prepare(); session = "session1"; directory = explorer.runtime / session; directory.mkdir(); visible = explorer.mount_runtime / session; visible.mkdir()
    events = []
    monkeypatch.setattr(explorer, "is_mount", lambda _path: False)
    monkeypatch.setattr(explorer, "_nbd_detached", lambda _dev: False)
    monkeypatch.setattr(explorer, "_wait_nbd_detached", lambda dev: events.append(("detached", dev)) or True)
    monkeypatch.setattr(explorer, "_run", lambda argv, **_kwargs: events.append(("run", argv)))
    monkeypatch.setattr(explorer, "_terminate", lambda process: events.append(("terminate", process["pid"])))
    monkeypatch.setattr(explorer, "_checkpoint", lambda state: events.append(("checkpoint", tuple(state["attached"]))))
    state = {"session_id": session, "caller_uid": explorer.uid, "caller_gid": explorer.gid,
             "directory": str(directory), "pinned": str(directory / "repository"),
             "mountpoint": str(visible / "files"), "pids": [{"pid": 10, "argv": ["/usr/bin/partclone-nbd"]}],
             "nbds": ["/dev/nbd0", "/dev/nbd1"], "attached": ["/dev/nbd0", "/dev/nbd1"], "mounted": False}
    explorer._cleanup(state, False)
    detach_positions = [index for index, event in enumerate(events) if event[0] == "detached"]
    terminate_position = next(index for index, event in enumerate(events) if event[0] == "terminate")
    assert detach_positions and max(detach_positions) < terminate_position
    assert state["attached"] == []


def test_partclone_readiness_uses_kernel_nbd_owner(tmp_path):
    sys_block = tmp_path / "sys"
    (sys_block / "nbd2").mkdir(parents=True)
    (sys_block / "nbd2" / "pid").write_text("123\n")
    (sys_block / "nbd2" / "size").write_text("1\n")
    process = type("Process", (), {"pid": 123, "stdout": None,
                                     "poll": lambda self: None})()
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts",
                             sys_block=sys_block)
    explorer._wait_ready(process, "/dev/nbd2")


def test_partclone_readiness_accepts_attached_device_size(tmp_path):
    sys_block = tmp_path / "sys"
    (sys_block / "nbd2").mkdir(parents=True)
    (sys_block / "nbd2" / "size").write_text("4096\n")
    process = type("Process", (), {"pid": 123, "stdout": None,
                                     "poll": lambda self: None})()
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts",
                             sys_block=sys_block)
    explorer._wait_ready(process, "/dev/nbd2")


def test_nbd_detach_waits_for_kernel_state(tmp_path):
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts",
                             sleep=lambda _seconds: None)
    states = iter((False, False, True))
    explorer._nbd_detached = lambda _device: next(states)
    assert explorer._wait_nbd_detached("/dev/nbd0")


def test_state_is_root_private_and_bad_permissions_are_rejected(tmp_path, monkeypatch):
    explorer = ImageExplorer(runtime=tmp_path, mount_runtime=tmp_path / "mounts")
    explorer._prepare()
    directory = tmp_path / "session1"; directory.mkdir(); visible = tmp_path / "mounts" / "session1"; visible.mkdir()
    state = {"session_id": "session1", "caller_uid": explorer.uid, "caller_gid": explorer.gid, "directory": str(directory), "mountpoint": str(visible / "files"), "pinned": str(directory / "repository"), "pids": [], "nbds": [], "attached": [], "mounted": False}
    explorer._write_state(state)
    path = tmp_path / "session1.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    os.chmod(path, 0o644)
    with pytest.raises(ImageExplorerError, match="invalid explorer state"): explorer._read_state("session1")


def test_busy_unmount_leaves_recorded_state_for_retry(tmp_path, monkeypatch):
    explorer = ImageExplorer(runtime=tmp_path, mount_runtime=tmp_path / "mounts", execute=lambda *_args, **_kwargs: 1, is_mount=lambda _path: True)
    explorer._prepare(); directory = tmp_path / "session1"; directory.mkdir(); user = tmp_path / "mounts" / "session1"; user.mkdir(); state = {"session_id": "session1", "caller_uid": explorer.uid, "caller_gid": explorer.gid, "directory": str(directory), "mountpoint": str(user / "files"), "pinned": str(directory / "repository"), "pids": [], "nbds": [], "attached": [], "mounted": True}; explorer._write_state(state)
    result = explorer.handle(ExplorerRequest("request1", "disconnect", session_id="session1"))
    assert result.status == "failed" and (tmp_path / "session1.json").exists()


def test_root_mount_hierarchy_and_cross_caller_state_rejection(tmp_path):
    runtime, mounts = tmp_path / "run" / "explorer", tmp_path / "run" / "explorer-mounts"
    explorer = ImageExplorer(runtime=runtime, mount_runtime=mounts, caller_uid=1001)
    explorer._prepare()
    assert stat.S_IMODE(runtime.parent.stat().st_mode) == 0o711
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
    assert stat.S_IMODE(mounts.stat().st_mode) == 0o711
    session = "session1"; directory = runtime / session; directory.mkdir(); visible = mounts / session; visible.mkdir()
    state = {"session_id": session, "caller_uid": 1002, "caller_gid": 1002, "directory": str(directory),
             "mountpoint": str(visible / "files"), "pinned": str(directory / "repository"),
             "pids": [], "nbds": [], "attached": [], "mounted": False}
    explorer._write_state(state)
    result = explorer.handle(ExplorerRequest("request1", "status", session_id=session))
    assert result.status == "failed" and "another caller" in result.detail


def test_fd_repository_pin_uses_proc_fd_and_closes_descriptor(tmp_path, monkeypatch):
    repository = tmp_path / "repository"; repository.mkdir(); explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts")
    closed = []; original_close = os.close
    monkeypatch.setattr(os, "close", lambda fd: (closed.append(fd), original_close(fd))[1])
    with explorer._repository_fd(str(repository)) as fd:
        assert f"/proc/{os.getpid()}/fd/{fd}" != str(repository)
    assert closed


def test_repository_bind_uses_runner_fd_not_caller_path(tmp_path):
    repository = tmp_path / "repository"; repository.mkdir()
    pinned = tmp_path / "pinned"; pinned.mkdir()
    commands = []
    explorer = ImageExplorer(
        runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts",
        execute=lambda argv, **_kwargs: commands.append(argv) or 0,
    )
    explorer._pin_repository(str(repository), pinned)
    assert commands[0][0:2] == ("/bin/mount", "--bind")
    assert commands[0][2].startswith(f"/proc/{os.getpid()}/fd/")
    assert str(repository) not in commands[0]


def test_runtime_symlink_is_rejected_without_changing_target_mode(tmp_path):
    target = tmp_path / "target"; target.mkdir(mode=0o755)
    runtime = tmp_path / "runtime"; runtime.symlink_to(target, target_is_directory=True)
    explorer = ImageExplorer(runtime=runtime, mount_runtime=tmp_path / "mounts")
    with pytest.raises(ImageExplorerError, match="invalid explorer runtime"):
        explorer._safe_dir(runtime, os.geteuid(), os.getegid(), 0o700)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_mount_parent_is_root_private_and_grants_only_caller_traverse(tmp_path, monkeypatch):
    commands = []
    explorer = ImageExplorer(runtime=tmp_path / "run", mount_runtime=tmp_path / "mounts", caller_uid=1001)
    monkeypatch.setattr(explorer, "_run", lambda argv, **_kwargs: commands.append(argv))
    monkeypatch.setattr(os, "chown", lambda *_args: None)
    parent = tmp_path / "mounts" / "session"
    parent.parent.mkdir()
    explorer._mount_parent(parent)
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert commands == [("/usr/bin/setfacl", "-m", "u:1001:--x,m::--x,g::---,o::---", str(parent))]
