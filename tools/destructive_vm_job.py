#!/usr/bin/env python3
"""Run an explicitly selected destructive VM fixture through the real runner."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if SOURCE_ROOT.is_dir():
    sys.path.insert(0, str(SOURCE_ROOT))
elif Path("/usr/lib/transume").is_dir():
    sys.path.insert(0, "/usr/lib/transume")

from transume.domain import JobOperation, PublicJobSpec  # noqa: E402
from transume.inventory import scan_block_devices  # noqa: E402
from transume.draft import image_fingerprint  # noqa: E402
from transume.protocol import PROTOCOL_VERSION, read_message, write_message  # noqa: E402

AUTHORIZED_VM_DEVICES = frozenset({"/dev/sda", "/dev/sdb"})


def find_device(serial: str, partition: int | None = None):
    matches = [item for item in scan_block_devices() if item.serial == serial]
    if len(matches) != 1:
        raise RuntimeError(f"expected one disk with serial {serial}, found {len(matches)}")
    disk = matches[0]
    if disk.path not in AUTHORIZED_VM_DEVICES:
        raise RuntimeError(
            f"refusing {disk.path}: destructive VM qualification is restricted to "
            f"{', '.join(sorted(AUTHORIZED_VM_DEVICES))}"
        )
    if partition is None:
        return disk.identity()
    suffix = f"p{partition}" if disk.name[-1:].isdigit() else str(partition)
    children = [item for item in disk.children if item.name == disk.name + suffix]
    if len(children) != 1:
        raise RuntimeError(f"expected partition {partition} on {disk.path}, found {len(children)}")
    return children[0].identity()


def execute(spec: PublicJobSpec, *, cancel_after: float | None = None,
            cancel_on_write: bool = False, passphrase: str | None = None) -> dict:
    action = "check" if spec.operation is JobOperation.CHECK_IMAGE else "write"
    source_runner = ROOT / "bin" / "transume-runner"
    runner = source_runner if source_runner.is_file() else Path("/usr/lib/transume/transume-runner")
    process = subprocess.Popen(
        [str(runner), action, "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    write_message(process.stdin, {"type": "hello", "version": PROTOCOL_VERSION})
    if read_message(process.stdout)["type"] != "hello":
        raise RuntimeError("runner handshake failed")
    write_message(process.stdin, {
        "type": "job", "version": PROTOCOL_VERSION, "spec": spec.to_dict(),
    })
    if passphrase is not None:
        write_message(process.stdin, {
            "type": "secret", "version": PROTOCOL_VERSION, "value": passphrase,
        })
    cancel_started = False
    def cancel() -> None:
        time.sleep(cancel_after or 0)
        write_message(process.stdin, {"type": "cancel", "version": PROTOCOL_VERSION})
        process.stdin.close()

    if cancel_after is None:
        process.stdin.close()
    elif not cancel_on_write:
        threading.Thread(target=cancel, name="vm-cancel", daemon=True).start()
    while True:
        result = read_message(process.stdout)
        if result["type"] == "result":
            break
        if result["type"] == "progress" and result["kind"] in {"progress", "stage", "warning", "error"}:
            percent = "" if result["percent"] is None else f" {result['percent']:.1f}%"
            print(f"[{result['kind']}]{percent} {result['message']}", flush=True)
            if (cancel_on_write and not cancel_started
                    and ("Cloning the /dev/" in result["message"]
                         or "Restoring partition /dev/" in result["message"])):
                cancel_started = True
                threading.Thread(target=cancel, name="vm-cancel-write", daemon=True).start()
    returncode = process.wait()
    expected = "cancelled" if cancel_after is not None else "ok"
    expected_code = 1 if cancel_after is not None else 0
    if result["status"] != expected or returncode != expected_code:
        stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
        raise RuntimeError(
            f"runner failed: status={result['status']} code={returncode} {result['detail']}\n{stderr}"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("save", "restore", "clone", "cancel-clone", "check"))
    parser.add_argument("--source-serial", required=True)
    parser.add_argument("--extra-source-serial", action="append", default=[])
    parser.add_argument("--extra-source-partition", action="append", type=int, default=[])
    parser.add_argument("--target-serial")
    parser.add_argument("--extra-target-serial", action="append", default=[])
    parser.add_argument("--extra-target-partition", action="append", type=int, default=[])
    parser.add_argument("--source-partition", type=int)
    parser.add_argument("--image-partition")
    parser.add_argument("--target-partition", type=int)
    parser.add_argument("--cancel-after", type=float, default=1.0)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--image", default="transume-roundtrip")
    parser.add_argument("--compression", choices=("zstd", "lz4", "gzip", "xz", "lzma", "none"), default="zstd")
    parser.add_argument("--rescue", action="store_true")
    parser.add_argument("--checksum", choices=("none", "md5", "sha1", "files"), default="none")
    parser.add_argument("--split-size", type=int, default=0, metavar="MIB")
    parser.add_argument("--encrypt", "--encrypted", action="store_true")
    args = parser.parse_args()
    source = find_device(args.source_serial, args.source_partition)
    sources = (source,
               *(find_device(args.source_serial, number) for number in args.extra_source_partition),
               *(find_device(serial, None) for serial in args.extra_source_serial))
    target = find_device(args.target_serial, args.target_partition) if args.target_serial else None
    targets = (((target,) if target is not None else ())
               + tuple(find_device(args.target_serial, number)
                       for number in args.extra_target_partition)
               + tuple(find_device(serial, None) for serial in args.extra_target_serial))
    common = {"job_id": f"vm-{args.operation}", "repository": args.repository,
              "image_name": args.image}
    if args.operation == "save":
        spec = PublicJobSpec(
            operation=(JobOperation.SAVEPARTS if source.device_type == "part" else JobOperation.SAVEDISK),
            sources=sources, risk="write-image",
            options={"compression": args.compression, "engine": "partclone",
                     "verify_image": True, "encrypt": args.encrypt,
                     "rescue": args.rescue, "checksum": args.checksum,
                     "image_size": args.split_size}, **common,
        )
    elif args.operation == "restore":
        if target is None:
            parser.error("restore requires --target-serial")
        restore_options = {"partition_table": "existing" if args.target_partition else "original",
                           "check_image": True,
                           "restore_mbr": not bool(args.target_partition),
                           "restore_ebr": not bool(args.target_partition),
                           "update_efi": not bool(args.target_partition),
                           "encrypted": args.encrypt}
        if args.image_partition:
            restore_options["source_partition"] = args.image_partition
        spec = PublicJobSpec(
            operation=(JobOperation.RESTOREPARTS if target.device_type == "part" else JobOperation.RESTOREDISK),
            destinations=targets,
            risk="destructive", options=restore_options,
            image_fingerprint=image_fingerprint(Path(args.repository) / args.image),
            **common,
        )
    elif args.operation in {"clone", "cancel-clone"}:
        if target is None:
            parser.error("clone requires --target-serial")
        if len(sources) != 1 or len(targets) != 1:
            parser.error("clone accepts exactly one source and target")
        spec = PublicJobSpec(
            job_id="vm-clone",
            operation=(JobOperation.CLONE_PART if source.device_type == "part" else JobOperation.CLONE_DISK),
            sources=(source,), destinations=(target,), risk="destructive",
            options={"direct_io": True, "rescue": args.rescue},
        )
    else:
        spec = PublicJobSpec(
            operation=JobOperation.CHECK_IMAGE, risk="read-only",
            image_fingerprint=image_fingerprint(Path(args.repository) / args.image),
            **common,
        )
    passphrase = os.environ.get("TRANSUME_TEST_PASSPHRASE") if args.encrypt else None
    if args.encrypt and not passphrase:
        parser.error("encrypted qualification requires TRANSUME_TEST_PASSPHRASE")
    result = execute(
        spec,
        cancel_after=args.cancel_after if args.operation == "cancel-clone" else None,
        cancel_on_write=args.operation == "cancel-clone",
        passphrase=passphrase,
    )
    print(f"{result['status']}: {result['detail']} cleanup={result['cleanup']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
