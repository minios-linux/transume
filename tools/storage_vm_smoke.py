#!/usr/bin/env python3
"""Destructive-in-/run SSHFS lifecycle qualification for an isolated VM."""

from __future__ import annotations

import argparse
import os
import pwd
import subprocess
from pathlib import Path

from transume.storage import (PrivilegedStorage, StorageKind, StorageLocation, StorageRequest,
                                scan_ssh_host_keys, ssh_host_key_fingerprint)


def request(identifier: str, operation: str, host: str, endpoint: str,
            username: str, port: int, password: str | None = None, host_key: str | None = None) -> StorageRequest:
    location = StorageLocation(
        StorageKind.SSH, "/run/transume/pending", host=host,
        endpoint=endpoint, username=username, port=port,
    )
    credentials = ({"password": password} if password is not None else {})
    if host_key is not None:
        credentials["host_key"] = host_key
    return StorageRequest(identifier, operation, location, credentials)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--endpoint", required=True)
    args = parser.parse_args()

    account = pwd.getpwnam(args.username)
    storage = PrivilegedStorage(caller_uid=account.pw_uid, caller_gid=account.pw_gid)
    keys = scan_ssh_host_keys(args.host, args.port)
    approved_key = next((key for key in keys if key.split()[1] == "ssh-ed25519"), keys[0])
    assert ssh_host_key_fingerprint(approved_key).startswith("SHA256:")
    good = request("sshfs-smoke-good", "mount", args.host, args.endpoint,
                   args.username, args.port, args.password, approved_key)
    mounted = storage.handle(good)
    assert mounted.status == "ok" and mounted.root
    root = Path(mounted.root)
    marker = root.parent / "sshfs-smoke-good.marker"
    assert root.is_mount() and marker.is_file()
    assert args.password not in marker.read_text(encoding="ascii")
    probe = root / "transume-sshfs-smoke"
    subprocess.run(
        ("runuser", "-u", args.username, "--", "touch", str(probe)),
        check=True, timeout=10,
    )
    assert (Path(args.endpoint) / probe.name).is_file()
    probe.unlink()

    unmount = request("sshfs-smoke-good", "unmount", args.host, args.endpoint,
                      args.username, args.port)
    result = storage.handle(unmount)
    assert result.status == "ok"
    assert not root.exists() and not marker.exists()

    # This second mount deliberately omits approval and must reuse the strict
    # root-owned known_hosts entry established by the first mount.
    bad = request("sshfs-smoke-bad", "mount", args.host, args.endpoint,
                   args.username, args.port, args.password + "-wrong")
    failed = storage.handle(bad)
    assert failed.status == "failed"
    assert not Path("/run/transume/mounts/sshfs-smoke-bad").exists()
    assert not Path("/run/transume/mounts/sshfs-smoke-bad.marker").exists()
    assert not any(Path("/run/transume").glob("credentials-*"))
    print("SSHFS approved-key mount, strict known-host reuse, unmount, and failure rollback passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
