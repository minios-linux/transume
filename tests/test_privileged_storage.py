import os
import socket
import subprocess
import base64
from pathlib import Path

import pytest

from transume.protocol import PROTOCOL_VERSION, decode_frame, encode_message
from transume.storage import (
    PrivilegedStorage,
    StorageKind,
    StorageLocation,
    StorageRequest,
    normalized_known_host_token,
    parse_ssh_host_key,
    scan_ssh_host_keys,
    ssh_host_key_fingerprint,
)


def smb_request(operation="mount", **kwargs):
    return StorageRequest("request-1", operation,
                          StorageLocation(StorageKind.SMB, "/ignored/by/runner",
                                          host="files.example", share="images", endpoint="/unused"),
                          **kwargs)


class MountTable:
    def __init__(self, fail=False, timeout=False):
        self.mounted = set()
        self.entries = {}
        self.calls = []
        self.fail = fail
        self.timeout = timeout

    def run(self, argv, *, timeout, input=None):
        self.calls.append((argv, input))
        if self.timeout:
            raise subprocess.TimeoutExpired(argv, timeout)
        if self.fail and argv[0] in {"mount", "sshfs"}:
            return 1
        if argv[0] == "mount":
            self.mounted.add(argv[4])
            self.entries[argv[4]] = ("cifs", argv[3])
        elif argv[0] == "sshfs":
            self.mounted.add(argv[-3])
            self.entries[argv[-3]] = ("fuse.sshfs", argv[-4])
        else:
            self.mounted.discard(argv[-1])
            self.entries.pop(argv[-1], None)
        return 0

    def mountinfo(self):
        lines = []
        for root in self.mounted:
            filesystem, source = self.entries[root]
            lines.append(f"1 0 0:1 / {root} rw - {filesystem} {source} rw")
        return "\n".join(lines)


def service(tmp_path, table):
    runtime = tmp_path / "run"
    storage = PrivilegedStorage(base=runtime / "mounts", runtime=runtime,
                                state=runtime / "state",
                                execute=table.run, is_mount=lambda root: root in table.mounted,
                                mountinfo=table.mountinfo,
                               which=lambda _name, **_kwargs: "/usr/bin/sshfs",
                               caller_uid=os.getuid())
    storage._fuse_allows_other = lambda: True  # type: ignore[method-assign]
    return storage


def test_storage_request_is_exact_and_rejects_injection_fields():
    request = smb_request(credentials={"username": "operator", "password": "private"})
    encoded = encode_message({"type": "storage-request", "version": PROTOCOL_VERSION, "request": request.to_dict()})
    assert decode_frame(encoded)["request"]["request_id"] == "request-1"
    payload = request.to_dict()
    payload["unexpected"] = "mount /evil"
    with pytest.raises(ValueError, match="unknown"):
        StorageRequest.from_dict(payload)
    with pytest.raises(ValueError):
        StorageLocation(StorageKind.SMB, "/tmp/x", host="files;touch", share="images", endpoint="/x")


def test_mount_keeps_credentials_private_and_writes_owned_marker(tmp_path):
    table = MountTable()
    result = service(tmp_path, table).handle(smb_request(credentials={"username": "operator", "password": "secret-value"}))
    marker = tmp_path / "run/mounts/request-1.marker"
    assert result.status == "ok"
    assert result.root == str(tmp_path / "run/mounts/request-1")
    assert "secret-value" not in str(table.calls)
    assert "secret-value" not in marker.read_text()
    assert os.stat(marker).st_uid == os.geteuid()
    assert os.stat(marker).st_mode & 0o777 == 0o600
    root_info = os.stat(tmp_path / "run/mounts/request-1")
    assert root_info.st_uid == os.getuid()
    assert root_info.st_gid == os.getgid()
    assert root_info.st_mode & 0o777 == 0o700
    assert os.stat(tmp_path / "run/mounts").st_mode & 0o777 == 0o711
    options = table.calls[0][0][-1]
    assert f"uid={os.getuid()}" in options
    assert f"gid={os.getgid()}" in options
    credential = options.split("credentials=", 1)[1]
    assert not Path(credential).exists()


def test_mount_failure_and_timeout_cleanup_without_leaking_secret(tmp_path):
    for table in (MountTable(fail=True), MountTable(timeout=True)):
        result = service(tmp_path, table).handle(smb_request(credentials={"password": "do-not-leak"}))
        assert result.status == "failed"
        assert "do-not-leak" not in result.detail
        assert not (tmp_path / "run/mounts/request-1").exists()
        assert not (tmp_path / "run/mounts/request-1.marker").exists()


def test_smb_authentication_failure_is_safely_classified(tmp_path):
    class Result:
        returncode = 32
        stderr = b"mount error(13): Permission denied"

    storage = PrivilegedStorage(
        base=tmp_path / "run/mounts", runtime=tmp_path / "run",
        state=tmp_path / "state", execute=lambda *_args, **_kwargs: Result(),
        is_mount=lambda _root: False, caller_uid=os.getuid(),
    )
    result = storage.handle(smb_request(credentials={"username": "operator", "password": "wrong-secret"}))
    assert result.status == "failed"
    assert result.detail == "SMB authentication failed"
    assert result.error_code == "authentication-failed"
    assert "wrong-secret" not in repr(result)


def test_unmount_requires_matching_root_owned_marker_and_protects_external_path(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    assert storage.handle(smb_request()).status == "ok"
    result = storage.handle(smb_request("unmount"))
    assert result.status == "ok"
    assert table.calls[-1][0][:2] == ("umount", "--")
    assert not (tmp_path / "run/mounts/request-1").exists()

    table.calls.clear()
    result = storage.handle(smb_request("unmount"))
    assert result.status == "not-mounted"
    assert table.calls == []


def test_unmount_rejects_a_different_caller(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    assert storage.handle(smb_request()).status == "ok"
    other = PrivilegedStorage(base=tmp_path / "run/mounts", runtime=tmp_path / "run",
                               execute=table.run, is_mount=lambda root: root in table.mounted,
                               mountinfo=table.mountinfo,
                              caller_uid=65534)
    result = other.handle(smb_request("unmount"))
    assert result.status == "failed"
    assert result.detail == "storage operation failed"
    assert table.calls[-1][0][0] == "mount"


def test_unmount_accepts_remote_root_with_arbitrary_ownership_and_rejects_mountinfo_mismatch(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    assert storage.handle(smb_request()).status == "ok"
    root = tmp_path / "run/mounts/request-1"
    if os.geteuid() == 0:
        os.chown(root, 4242, 4242)  # A remote filesystem's apparent root ownership is not caller identity.
    assert storage.handle(smb_request("unmount")).status == "ok"

    assert storage.handle(smb_request()).status == "ok"
    table.entries[str(root)] = ("nfs", "files.example:/wrong")
    assert storage.handle(smb_request("unmount")).status == "failed"
    assert str(root) in table.mounted


def ssh_request(operation="mount", **kwargs):
    return StorageRequest("request-1", operation,
                          StorageLocation(StorageKind.SSH, "/ignored/by/runner",
                                          host="files.example", endpoint="/images",
                                          username="operator", port=2222),
                          **kwargs)


def test_sshfs_argv_uses_tofu_and_password_input_only(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    # The production check requires root ownership. The command test runs unprivileged,
    # so retain the generated path while testing argv and stdin isolation separately.
    known_hosts = tmp_path / "run/known_hosts"
    known_hosts.parent.mkdir(parents=True)
    known_hosts.touch(mode=0o600)
    storage._known_hosts = lambda: known_hosts  # type: ignore[method-assign]
    password = "private-value"
    key = "[files.example]:2222 ssh-ed25519 " + base64.b64encode(b"approved-host-key-material").decode()
    result = storage.handle(ssh_request(credentials={"password": password, "host_key": key}, read_only=True))
    argv, supplied = table.calls[0]
    assert result.status == "ok"
    assert argv[:3] == ("sshfs", "-p", "2222")
    assert argv[3] == "operator@files.example:/images"
    assert "password_stdin" in argv[-1]
    assert "StrictHostKeyChecking=yes" in argv[-1]
    assert "StrictHostKeyChecking=accept-new" not in argv[-1]
    assert "StrictHostKeyChecking=no" not in argv[-1]
    assert "nosuid,nodev,noexec,reconnect" in argv[-1]
    assert "allow_other" in argv[-1]
    assert "default_permissions" in argv[-1]
    assert password not in str(argv)
    assert supplied == (password + "\n").encode()
    marker = tmp_path / "run/mounts/request-1.marker"
    assert password not in marker.read_text()
    assert storage.handle(ssh_request("unmount")).status == "ok"


def test_sshfs_requires_root_configured_allow_other(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    storage._fuse_allows_other = lambda: False  # type: ignore[method-assign]
    assert storage.handle(ssh_request()).status == "failed"
    assert table.calls == []


def test_ssh_rejects_unsafe_known_hosts_and_cleans_mount_root(tmp_path):
    table = MountTable()
    runtime = tmp_path / "run"
    runtime.mkdir()
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / f"known_hosts-{os.getuid()}").symlink_to(tmp_path / "elsewhere")
    storage = PrivilegedStorage(base=runtime / "mounts", runtime=runtime, execute=table.run,
                                state=state,
                                is_mount=lambda root: root in table.mounted,
                                which=lambda _name, **_kwargs: "/usr/bin/sshfs",
                                caller_uid=os.getuid())
    storage._fuse_allows_other = lambda: True  # type: ignore[method-assign]
    result = storage.handle(ssh_request(credentials={"password": "secret"}))
    assert result.status == "failed"
    assert "secret" not in repr(result)
    assert not (runtime / "mounts/request-1").exists()


def test_known_hosts_is_created_mode_0600_and_requires_runner_ownership(tmp_path):
    storage = service(tmp_path, MountTable())
    storage._prepare_base()
    known_hosts = storage._known_hosts()
    assert known_hosts.stat().st_mode & 0o777 == 0o600
    assert known_hosts.stat().st_uid == os.geteuid()


@pytest.mark.parametrize("kwargs", [
    {"host": "bad;host", "endpoint": "/images", "username": "operator"},
    {"host": "files.example", "endpoint": "relative", "username": "operator"},
    {"host": "files.example", "endpoint": "/images", "username": "bad@name"},
    {"host": "files.example", "endpoint": "/images", "username": "operator", "port": 0},
])
def test_ssh_location_rejects_invalid_values(kwargs):
    with pytest.raises(ValueError):
        StorageLocation(StorageKind.SSH, "/mnt/images", **kwargs)


def test_ssh_request_rejects_unknown_credentials():
    with pytest.raises(ValueError):
        ssh_request(credentials={"username": "operator"})


def test_password_is_not_exposed_by_request_representation():
    request = ssh_request(credentials={"password": "never-display"})
    assert "never-display" not in repr(request)


def test_ssh_host_key_helpers_normalize_and_reject_mismatches():
    encoded = base64.b64encode(b"approved-host-key-material").decode()
    assert normalized_known_host_token("EXAMPLE.test", None) == "example.test"
    assert normalized_known_host_token("192.0.2.9", 2222) == "[192.0.2.9]:2222"
    assert normalized_known_host_token("2001:0db8::1", 2222) == "[2001:db8::1]:2222"
    line = "[2001:db8::1]:2222 ssh-ed25519 " + encoded
    assert parse_ssh_host_key(line, "[2001:db8::1]:2222")[0] == "ssh-ed25519"
    assert ssh_host_key_fingerprint(line).startswith("SHA256:")
    with pytest.raises(ValueError):
        parse_ssh_host_key("other.example ssh-ed25519 " + encoded, "example.test")
    with pytest.raises(ValueError):
        parse_ssh_host_key("example.test ssh-ed25519 bad!")


def test_keyscan_uses_absolute_argv_and_only_exact_safe_lines():
    encoded = base64.b64encode(b"approved-host-key-material").decode()
    calls = []
    result = type("Result", (), {"returncode": 0, "stdout": (
        "[example.test]:2222 ssh-ed25519 " + encoded + "\n"
        "other.example ssh-ed25519 " + encoded + "\n"
    )})()
    keys = scan_ssh_host_keys("example.test", 2222,
                              run=lambda *args, **kwargs: calls.append((args, kwargs)) or result)
    assert keys == ("[example.test]:2222 ssh-ed25519 " + encoded,)
    assert calls[0][0][0] == ("/usr/bin/ssh-keyscan", "-T", "10", "-p", "2222", "example.test")
    assert calls[0][1]["shell"] is False


def test_sshfs_rejects_unapproved_host_before_password_or_mount(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    known_hosts = tmp_path / "run/known_hosts"; known_hosts.parent.mkdir(parents=True); known_hosts.touch(mode=0o600)
    storage._known_hosts = lambda: known_hosts  # type: ignore[method-assign]
    result = storage.handle(ssh_request(credentials={"password": "private"}))
    assert result.status == "failed"
    assert table.calls == []


def test_approved_ssh_host_key_is_deduplicated(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    known_hosts = tmp_path / "run/known_hosts"; known_hosts.parent.mkdir(parents=True); known_hosts.touch(mode=0o600)
    storage._known_hosts = lambda: known_hosts  # type: ignore[method-assign]
    key = "[files.example]:2222 ssh-ed25519 " + base64.b64encode(b"approved-host-key-material").decode()
    assert storage.handle(ssh_request(credentials={"password": "private", "host_key": key})).status == "ok"
    assert storage.handle(ssh_request("unmount")).status == "ok"
    assert storage.handle(ssh_request("mount", credentials={"password": "private", "host_key": key})).status == "ok"
    assert known_hosts.read_text().splitlines() == [key]


def test_ssh_private_key_and_agent_modes_do_not_enable_password_stdin(tmp_path):
    key_line = "[files.example]:2222 ssh-ed25519 " + base64.b64encode(b"approved-host-key-material").decode()

    key_table = MountTable()
    key_storage = service(tmp_path / "key", key_table)
    identity = tmp_path / "identity"
    identity.write_text("private key")
    identity.chmod(0o600)
    result = key_storage.handle(ssh_request(credentials={
        "auth_method": "private-key", "identity_file": str(identity), "host_key": key_line,
    }))
    assert result.status == "ok"
    options = key_table.calls[0][0][-1]
    assert f"IdentityFile={identity}" in options
    assert "IdentitiesOnly=yes" in options and "BatchMode=yes" in options
    assert "password_stdin" not in options and key_table.calls[0][1] is None

    agent_table = MountTable()
    agent_storage = service(tmp_path / "agent", agent_table)
    agent_dir = tmp_path / "agent-socket"
    agent_dir.mkdir(mode=0o700)
    agent = socket.socket(socket.AF_UNIX)
    socket_path = agent_dir / "agent.sock"
    agent.bind(str(socket_path))
    try:
        result = agent_storage.handle(ssh_request(credentials={
            "auth_method": "agent", "agent_socket": str(socket_path), "host_key": key_line,
        }))
        assert result.status == "ok"
        options = agent_table.calls[0][0][-1]
        assert f"IdentityAgent={socket_path}" in options
        assert "BatchMode=yes" in options and "password_stdin" not in options
    finally:
        agent.close()


def test_ssh_rejects_changed_pinned_host_key(tmp_path):
    table = MountTable()
    storage = service(tmp_path, table)
    first = "[files.example]:2222 ssh-ed25519 " + base64.b64encode(b"first-approved-host-key").decode()
    changed = "[files.example]:2222 ssh-ed25519 " + base64.b64encode(b"changed-host-key-value").decode()
    assert storage.handle(ssh_request(credentials={"password": "private", "host_key": first})).status == "ok"
    assert storage.handle(ssh_request("unmount")).status == "ok"
    result = storage.handle(ssh_request(credentials={"password": "private", "host_key": changed}))
    assert result.status == "failed"
    assert result.detail == "SSH host key changed"
    assert table.calls[-1][0][0] == "umount"


@pytest.mark.parametrize("credentials", [
    {"auth_method": "password"},
    {"auth_method": "private-key", "password": "bad"},
    {"auth_method": "agent", "identity_file": "/tmp/key"},
    {"auth_method": "unknown"},
])
def test_ssh_request_rejects_invalid_authentication_shapes(credentials):
    with pytest.raises(ValueError):
        ssh_request(credentials=credentials)
