from pathlib import Path

import pytest

from transume.storage import (
    ConnectionState,
    MountOwnership,
    StorageError,
    StorageKind,
    StorageLocation,
    StorageManager,
    prepare_smb_subfolder,
)


class Recorder:
    def __init__(self, result=0):
        self.calls = []
        self.result = result

    def __call__(self, argv):
        self.calls.append(argv)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_location_canonicalizes_roots_and_endpoints():
    location = StorageLocation(StorageKind.NFS, "/mnt//images/", host="files.example", endpoint="//exports/images/")
    assert location.root == "/mnt/images"
    assert location.endpoint == "/exports/images"
    with pytest.raises(ValueError, match="path traversal"):
        StorageLocation(StorageKind.LOCAL_FOLDER, "/mnt/../images")
    with pytest.raises(ValueError, match="NUL"):
        StorageLocation(StorageKind.LOCAL_FOLDER, "/mnt/\x00images")


def test_smb_subfolder_is_created_without_following_links(tmp_path):
    mount_root = tmp_path / "share"
    mount_root.mkdir()
    assert prepare_smb_subfolder(mount_root, "/backup/nightly") == mount_root / "backup/nightly"
    assert (mount_root / "backup/nightly").is_dir()

    outside = tmp_path / "outside"
    outside.mkdir()
    (mount_root / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic links"):
        prepare_smb_subfolder(mount_root, "/escape/new")
    assert not (outside / "new").exists()


@pytest.mark.parametrize("kwargs", [
    {"host": "bad;host", "endpoint": "/images"},
    {"host": "files.example", "endpoint": "relative"},
    {"host": "files.example", "endpoint": "/images", "share": "bad/share"},
])
def test_network_locations_reject_invalid_fields(kwargs):
    with pytest.raises(ValueError):
        StorageLocation(StorageKind.SMB, "/mnt/images", **kwargs)


def test_session_state_machine_is_explicit():
    session = StorageManager(Recorder()).register(StorageLocation(StorageKind.NFS, "/mnt/nfs", host="host", endpoint="/export"))
    with pytest.raises(StorageError, match="cannot transition"):
        session.transition(ConnectionState.MOUNTED)
    session.transition(ConnectionState.CONNECTING)
    session.transition(ConnectionState.MOUNTED)
    assert session.state is ConnectionState.MOUNTED


def test_mount_uses_safe_argv_and_removes_credentials():
    executor = Recorder()
    manager = StorageManager(executor)
    session = manager.register(StorageLocation(StorageKind.SMB, "/mnt/share", host="files.example", share="images", endpoint="/unused"))
    manager.mount(session, {"username": "operator", "password": "not in argv"})
    argv = executor.calls[0]
    assert argv[:4] == ("mount", "-t", "cifs", "//files.example/images")
    credential_arg = argv[argv.index("-o") + 1]
    credential_path = credential_arg.removeprefix("credentials=")
    assert not Path(credential_path).exists()
    assert "not in argv" not in argv
    assert session.state is ConnectionState.MOUNTED


def test_external_mount_is_registered_without_commands_and_is_protected():
    executor = Recorder()
    manager = StorageManager(executor)
    session = manager.register_existing_local_folder("/already/mounted")
    assert session.ownership is MountOwnership.EXTERNAL
    with pytest.raises(StorageError, match="cannot unmount"):
        manager.unmount(session)
    assert executor.calls == []


def test_cleanup_continues_after_owned_unmount_failure():
    executor = Recorder(RuntimeError("busy"))
    manager = StorageManager(executor)
    first = manager.register(StorageLocation(StorageKind.BLOCK_DEVICE, "/mnt/a", device="/dev/sda1"))
    second = manager.register(StorageLocation(StorageKind.REMOVABLE, "/mnt/b", device="/dev/sdb1"))
    first.state = second.state = ConnectionState.MOUNTED
    errors = manager.cleanup_owned()
    assert errors == ("unmount failed: busy", "unmount failed: busy")
    assert first.state is second.state is ConnectionState.FAILED
