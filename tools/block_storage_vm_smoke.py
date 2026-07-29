#!/usr/bin/env python3
"""Qualify block/removable mount lifecycle around VM hotplug events."""
from __future__ import annotations

import argparse
import os
import pwd
import subprocess
from pathlib import Path

from transume.storage import PrivilegedStorage, StorageKind, StorageLocation, StorageRequest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--expect-unavailable", action="store_true")
    args = parser.parse_args()
    account = pwd.getpwnam(args.username)
    storage = PrivilegedStorage(caller_uid=account.pw_uid, caller_gid=account.pw_gid)
    for kind in (StorageKind.BLOCK_DEVICE, StorageKind.REMOVABLE):
        identifier = f"{kind.value}-smoke"
        location = StorageLocation(kind, "/run/transume/pending", device=args.device)
        mounted = storage.handle(StorageRequest(identifier, "mount", location))
        root = Path("/run/transume/mounts") / identifier
        marker = root.parent / f"{identifier}.marker"
        if args.expect_unavailable:
            if mounted.status != "failed" or root.exists() or marker.exists():
                raise RuntimeError(f"{kind.value} unavailable-device rollback failed")
            continue
        if mounted.status != "ok" or not mounted.root or not os.path.ismount(mounted.root):
            raise RuntimeError(f"{kind.value} mount failed")
        subprocess.run(
            ("runuser", "-u", args.username, "--", "test", "-r", mounted.root),
            check=True,
        )
        result = storage.handle(StorageRequest(identifier, "unmount", location))
        if result.status != "ok" or root.exists() or marker.exists():
            raise RuntimeError(f"{kind.value} unmount cleanup failed")
    state = "unavailable rollback" if args.expect_unavailable else "mount/unmount"
    print(f"Block-device and removable {state} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
