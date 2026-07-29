#!/usr/bin/env python3
"""Qualify supported Clonezilla workflows on the two disposable VM disks.

Run this script only inside the disposable VM. It refuses every source/target
block path except /dev/sda and /dev/sdb. The mounted /dev/sdc1 filesystem may
be used only as an image repository; its raw block path is never accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


AUTHORIZED = frozenset({"/dev/sda", "/dev/sdb"})
ROOT = Path(__file__).resolve().parent
JOB = ROOT / "destructive_vm_job.py"
EVIDENCE: Path | None = None


def record(event: str, **fields: object) -> None:
    line = json.dumps({"event": event, **fields}, sort_keys=True)
    print(line, flush=True)
    if EVIDENCE is not None:
        with EVIDENCE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def run(*argv: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    record("command", argv=list(argv))
    result = subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    record("result", argv=list(argv), returncode=result.returncode, output=result.stdout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(argv)}")
    return result


def require_authorized(path: str) -> None:
    disk = path.rstrip("0123456789")
    if disk not in AUTHORIZED:
        raise RuntimeError(f"refusing non-disposable device {path}")


def serial(disk: str) -> str:
    require_authorized(disk)
    value = run("/usr/bin/lsblk", "-dn", "-o", "SERIAL", disk).stdout.strip()
    if not value:
        raise RuntimeError(f"no stable serial for {disk}")
    return value


def sha256(path: str) -> str:
    return run("/usr/bin/sha256sum", path).stdout.split()[0]


def unmount_disk(disk: str) -> None:
    require_authorized(disk)
    mounts = run("/usr/bin/lsblk", "-nr", "-o", "MOUNTPOINTS", disk).stdout.splitlines()
    for mount in reversed([item.strip() for item in mounts if item.strip()]):
        run("/bin/umount", "--", mount)


def layout(disk: str, table: str, filesystem: str) -> str:
    require_authorized(disk)
    unmount_disk(disk)
    run("/usr/sbin/wipefs", "-a", "-f", disk)
    label = "label: gpt\n" if table == "gpt" else "label: dos\n"
    run("/usr/sbin/sfdisk", "--wipe", "always", disk,
        input_text=label + ",1536M\n")
    run("/usr/bin/udevadm", "settle")
    partition = f"{disk}1"
    formatters = {
        "ext4": ("/usr/sbin/mkfs.ext4", "-F", partition),
        "ntfs": ("/usr/sbin/mkfs.ntfs", "-F", "-Q", partition),
        "fat": ("/usr/sbin/mkfs.fat", "-F", "32", partition),
        "xfs": ("/usr/sbin/mkfs.xfs", "-f", partition),
    }
    run(*formatters[filesystem])
    return partition


def seed_and_hash(partition: str, name: str) -> str:
    require_authorized(partition)
    mountpoint = Path("/mnt/transume-qualification")
    mountpoint.mkdir(exist_ok=True)
    run("/bin/mount", "--", partition, str(mountpoint))
    try:
        payload = hashlib.sha256(name.encode("ascii")).digest() * 32768
        (mountpoint / "payload.bin").write_bytes(payload)
        (mountpoint / "marker.txt").write_text(f"{name}\n", encoding="ascii")
        run("/bin/sync")
        return sha256(str(mountpoint / "payload.bin"))
    finally:
        run("/bin/umount", "--", str(mountpoint))


def verify_content(partition: str, expected: str) -> None:
    require_authorized(partition)
    mountpoint = Path("/mnt/transume-qualification")
    run("/bin/mount", "--", partition, str(mountpoint))
    try:
        actual = sha256(str(mountpoint / "payload.bin"))
        if actual != expected:
            raise RuntimeError(f"content hash mismatch: {actual} != {expected}")
        record("content-verified", partition=partition, sha256=actual)
    finally:
        run("/bin/umount", "--", str(mountpoint))


def job(operation: str, source: str, target: str | None, repository: Path, image: str,
        *options: str) -> None:
    require_authorized(source)
    if target:
        require_authorized(target)
    command = [sys.executable, str(JOB), operation, "--source-serial", serial(source.rstrip("0123456789")),
               "--repository", str(repository), "--image", image, *options]
    if source[-1:].isdigit() and source[-2:] not in {"da", "db"}:
        command.extend(("--source-partition", source[-1:]))
    if target:
        command.extend(("--target-serial", serial(target.rstrip("0123456789"))))
        if target[-1:].isdigit() and target[-2:] not in {"da", "db"}:
            command.extend(("--target-partition", target[-1:]))
    run(*command)


def partition_roundtrip(repository: Path, filesystem: str) -> None:
    source = layout("/dev/sda", "gpt", filesystem)
    expected = seed_and_hash(source, f"gpt-{filesystem}")
    target = layout("/dev/sdb", "gpt", filesystem)
    image = f"gpt-{filesystem}"
    job("save", source, None, repository, image, "--compression", "zstd", "--checksum", "files")
    job("check", "/dev/sda", None, repository, image)
    job("restore", "/dev/sda", target, repository, image)
    verify_content(target, expected)
    record("qualified", capability="GPT partition backup/restore", filesystem=filesystem)


def disk_roundtrip(repository: Path, table: str) -> None:
    source = layout("/dev/sda", table, "ext4")
    expected = seed_and_hash(source, f"{table}-disk")
    layout("/dev/sdb", table, "ext4")
    image = f"{table}-disk"
    job("save", "/dev/sda", None, repository, image, "--compression", "zstd")
    job("check", "/dev/sda", None, repository, image)
    job("restore", "/dev/sda", "/dev/sdb", repository, image)
    verify_content("/dev/sdb1", expected)
    restored_table = run("/usr/bin/lsblk", "-dn", "-o", "PTTYPE", "/dev/sdb").stdout.strip()
    if restored_table != table:
        raise RuntimeError(f"partition table mismatch: {restored_table} != {table}")
    record("qualified", capability=f"{table.upper()} full-disk backup/restore",
           payload_sha256=expected, partition_table=restored_table)


def split_and_clone(repository: Path) -> None:
    source = layout("/dev/sda", "gpt", "ext4")
    expected = seed_and_hash(source, "split-and-rescue")
    target = layout("/dev/sdb", "gpt", "ext4")
    image = "split-ext4"
    job("save", source, None, repository, image, "--compression", "none", "--split-size", "1", "--rescue")
    image_dir = repository / image
    split_files = sorted(path.name for path in image_dir.glob("*.aa"))
    if not split_files:
        raise RuntimeError("expected split image payload suffix .aa")
    record("split-image", files=split_files)
    job("restore", "/dev/sda", target, repository, image)
    verify_content(target, expected)
    layout("/dev/sdb", "gpt", "ext4")
    job("clone", source, target, repository, "unused", "--rescue")
    verify_content(target, expected)
    record("qualified", capability="split image restore and rescue-mode partition clone")


def efi_roundtrip(repository: Path) -> None:
    for disk in ("/dev/sda", "/dev/sdb"):
        unmount_disk(disk)
        run("/usr/sbin/wipefs", "-a", "-f", disk)
        run("/usr/sbin/sfdisk", "--wipe", "always", disk,
            input_text="label: gpt\nsize=128M,type=U\nsize=1400M,type=L\n")
        run("/usr/bin/udevadm", "settle")
        run("/usr/sbin/mkfs.fat", "-F", "32", f"{disk}1")
        run("/usr/sbin/mkfs.ext4", "-F", f"{disk}2")
    mountpoint = Path("/mnt/transume-qualification")
    run("/bin/mount", "--", "/dev/sda1", str(mountpoint))
    try:
        (mountpoint / "EFI" / "BOOT").mkdir(parents=True)
        (mountpoint / "EFI" / "BOOT" / "BOOTX64.EFI").write_bytes(b"TRANSUME-EFI-FIXTURE\n")
        run("/bin/sync")
        esp_hash = sha256(str(mountpoint / "EFI" / "BOOT" / "BOOTX64.EFI"))
    finally:
        run("/bin/umount", "--", str(mountpoint))
    data_hash = seed_and_hash("/dev/sda2", "efi-data")
    image = "gpt-efi-disk"
    job("save", "/dev/sda", None, repository, image, "--compression", "zstd")
    job("check", "/dev/sda", None, repository, image)
    job("restore", "/dev/sda", "/dev/sdb", repository, image)
    run("/bin/mount", "--", "/dev/sdb1", str(mountpoint))
    try:
        if sha256(str(mountpoint / "EFI" / "BOOT" / "BOOTX64.EFI")) != esp_hash:
            raise RuntimeError("EFI system partition fixture hash mismatch")
    finally:
        run("/bin/umount", "--", str(mountpoint))
    verify_content("/dev/sdb2", data_hash)
    esp_type = run("/usr/bin/lsblk", "-dn", "-o", "PARTTYPE", "/dev/sdb1").stdout.strip().lower()
    if esp_type != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b":
        raise RuntimeError(f"EFI system partition type mismatch: {esp_type}")
    record("qualified", capability="GPT EFI system partition full-disk backup/restore",
           esp_sha256=esp_hash, data_sha256=data_hash, esp_type=esp_type)


def main() -> int:
    global EVIDENCE
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default="/tmp/transume-qualification-images")
    parser.add_argument("--evidence", default="/tmp/transume-qualification.jsonl")
    parser.add_argument("--only", choices=("all", "partitions", "disk", "split", "efi"), default="all")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("must run as root in the disposable VM")
    if not JOB.is_file():
        parser.error(f"missing helper: {JOB}")
    repository = Path(args.repository)
    EVIDENCE = Path(args.evidence)
    if EVIDENCE.resolve().is_relative_to(Path("/home/partimag")):
        parser.error("evidence must not reside on /dev/sdc1")
    EVIDENCE.unlink(missing_ok=True)
    shutil.rmtree(repository, ignore_errors=True)
    repository.mkdir(mode=0o700, parents=True)
    record("start", authorized_devices=sorted(AUTHORIZED), repository=str(repository))
    if args.only in {"all", "partitions"}:
        for filesystem in ("ext4", "ntfs", "fat", "xfs"):
            partition_roundtrip(repository, filesystem)
    if args.only in {"all", "disk"}:
        disk_roundtrip(repository, "gpt")
        disk_roundtrip(repository, "dos")
    if args.only in {"all", "split"}:
        split_and_clone(repository)
    if args.only in {"all", "efi"}:
        efi_roundtrip(repository)
    record("complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
