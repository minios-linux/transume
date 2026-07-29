"""Parsing and safety classification for lsblk JSON output."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from .domain import DeviceIdentity


@dataclass(frozen=True, slots=True)
class BlockDevice:
    name: str
    path: str
    device_type: str
    size: int
    mountpoints: tuple[str, ...]
    read_only: bool
    removable: bool
    filesystem: str | None
    children: tuple[BlockDevice, ...]
    is_mounted: bool
    is_system: bool
    is_live: bool
    is_swap: bool
    selectable_source: bool
    selectable_destination: bool
    major_minor: str | None = None
    serial: str | None = None
    wwn: str | None = None
    model: str | None = None
    vendor: str | None = None
    partition_table_type: str | None = None
    partition_table_uuid: str | None = None

    def identity(self) -> DeviceIdentity:
        if not self.major_minor:
            raise ValueError(f"device identity is incomplete: {self.path}")
        sysfs = Path("/sys/dev/block") / self.major_minor
        try:
            sysfs_path = str(sysfs.resolve(strict=True))
        except OSError as exc:
            raise ValueError(f"sysfs identity is unavailable: {self.path}") from exc
        by_id = []
        by_id_root = Path("/dev/disk/by-id")
        if by_id_root.is_dir():
            for link in by_id_root.iterdir():
                try:
                    if link.resolve(strict=True) == Path(self.path).resolve(strict=True):
                        by_id.append(str(link))
                except OSError:
                    continue
        if not (self.wwn or self.serial or by_id):
            raise ValueError(f"device has no stable identifier: {self.path}")
        return DeviceIdentity(
            path=self.path,
            sysfs_path=sysfs_path,
            major_minor=self.major_minor,
            device_type=self.device_type,
            size=self.size,
            wwn=self.wwn,
            serial=self.serial,
            by_id=tuple(sorted(by_id)),
            vendor=self.vendor,
            model=self.model,
            partition_table_type=self.partition_table_type,
            partition_table_uuid=self.partition_table_uuid,
            removable=self.removable,
        )


def parse_lsblk_json(payload: str | bytes) -> tuple[BlockDevice, ...]:
    try:
        root = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid lsblk JSON") from exc
    if not isinstance(root, dict) or set(root) != {"blockdevices"} or not isinstance(root["blockdevices"], list):
        raise ValueError("invalid lsblk schema")
    return tuple(_parse_device(item, False, False) for item in root["blockdevices"])


def scan_block_devices() -> tuple[BlockDevice, ...]:
    """Return the current block-device tree without requiring privileges."""
    command = (
        "/usr/bin/lsblk", "--json", "--bytes", "--paths",
        "--output", "NAME,PATH,TYPE,SIZE,RO,RM,FSTYPE,MOUNTPOINTS,MAJ:MIN,SERIAL,WWN,MODEL,VENDOR,PTTYPE,PTUUID",
    )
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
        env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "lsblk failed"
        raise RuntimeError(detail)
    return parse_lsblk_json(result.stdout)


def _parse_device(item: Any, parent_system: bool, parent_live: bool) -> BlockDevice:
    if not isinstance(item, dict):
        raise ValueError("block device must be an object")
    required = {"name", "type", "size"}
    if not required <= item.keys():
        raise ValueError("block device is missing required fields")
    name, kind, size = item["name"], item["type"], item["size"]
    if not isinstance(name, str) or not isinstance(kind, str) or isinstance(size, bool):
        raise ValueError("invalid block device fields")
    try:
        size = int(size)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid device size") from exc
    raw_mounts = item.get("mountpoints")
    if raw_mounts is None:
        raw_mounts = [item.get("mountpoint")]
    if not isinstance(raw_mounts, list):
        raise ValueError("mountpoints must be a list")
    mounts = tuple(x for x in raw_mounts if isinstance(x, str) and x)
    filesystem = item.get("fstype")
    swap = filesystem == "swap" or "[SWAP]" in mounts
    system = parent_system or any(x == "/" or x.startswith(("/boot", "/usr", "/var")) for x in mounts)
    live = parent_live or filesystem in {"squashfs", "iso9660"} or any(
        x.startswith(("/run/live", "/lib/live", "/cdrom")) for x in mounts)
    children = tuple(_parse_device(x, system, live) for x in item.get("children", ()))
    system = system or any(x.is_system for x in children)
    live = live or any(x.is_live for x in children)
    mounted = bool(mounts) or any(x.is_mounted for x in children)
    read_only = bool(item.get("ro", False))
    technical = kind in {"loop", "rom", "zram", "ram"}
    blocked = mounted or swap or system or live or technical
    return BlockDevice(
        name, item.get("path", f"/dev/{name}"), kind, size, mounts,
        read_only, bool(item.get("rm", False)), filesystem, children,
        mounted, system, live, swap, not blocked, not blocked and not read_only,
        item.get("maj:min"), item.get("serial"), item.get("wwn"), item.get("model"),
        item.get("vendor"), item.get("pttype"), item.get("ptuuid"),
    )
