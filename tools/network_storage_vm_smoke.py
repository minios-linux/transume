#!/usr/bin/env python3
"""Qualify real loopback SMB and NFS storage lifecycles in an isolated VM."""
from __future__ import annotations

import argparse
import pwd
import subprocess
from pathlib import Path

from transume.storage import PrivilegedStorage, StorageKind, StorageLocation, StorageRequest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("smb", "nfs"))
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--backing", type=Path, required=True)
    parser.add_argument("--test-server-restart", action="store_true")
    parser.add_argument("--service")
    args = parser.parse_args()
    account = pwd.getpwnam(args.username)
    storage = PrivilegedStorage(caller_uid=account.pw_uid, caller_gid=account.pw_gid)
    kind = StorageKind(args.kind)
    location = StorageLocation(
        kind, "/run/transume/pending", host="127.0.0.1",
        endpoint=str(args.backing) if kind is StorageKind.NFS else "/",
        share="transume" if kind is StorageKind.SMB else None,
    )
    credentials = ({"username": args.username, "password": args.password}
                   if kind is StorageKind.SMB else {})
    request = StorageRequest(f"{args.kind}-smoke", "mount", location, credentials)
    mounted = storage.handle(request)
    assert mounted.status == "ok" and mounted.root
    root = Path(mounted.root)
    probe = root / f"transume-{args.kind}-smoke"
    subprocess.run(("runuser", "-u", args.username, "--", "touch", str(probe)), check=True)
    assert (args.backing / probe.name).is_file()
    probe.unlink()
    result = storage.handle(StorageRequest(f"{args.kind}-smoke", "unmount", location))
    assert result.status == "ok" and not root.exists()
    if kind is StorageKind.SMB:
        bad = StorageRequest("smb-smoke-bad", "mount", location,
                             {"username": args.username, "password": args.password + "-wrong"})
        assert storage.handle(bad).status == "failed"
        assert not Path("/run/transume/mounts/smb-smoke-bad").exists()
        assert not any(Path("/run/transume").glob("credentials-*"))
    if args.test_server_restart:
        service = args.service or ("smbd" if kind is StorageKind.SMB else "nfs-kernel-server")
        subprocess.run(("systemctl", "stop", service), check=True)
        down = StorageRequest(f"{args.kind}-server-down", "mount", location, credentials)
        try:
            assert storage.handle(down).status == "failed"
            assert not Path(f"/run/transume/mounts/{args.kind}-server-down").exists()
            assert not Path(f"/run/transume/mounts/{args.kind}-server-down.marker").exists()
            assert not any(Path("/run/transume").glob("credentials-*"))
        finally:
            subprocess.run(("systemctl", "start", service), check=True)
        reconnect = StorageRequest(f"{args.kind}-reconnect", "mount", location, credentials)
        remounted = storage.handle(reconnect)
        assert remounted.status == "ok" and remounted.root
        assert storage.handle(StorageRequest(
            f"{args.kind}-reconnect", "unmount", location,
        )).status == "ok"
    print(f"{args.kind.upper()} mount, caller access, unmount, and rollback passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
