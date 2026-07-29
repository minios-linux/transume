#!/usr/bin/env python3
"""Exercise the real read-only explorer against an explicitly supplied fixture."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pwd
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src") if (ROOT / "src").is_dir() else "/usr/lib/transume")
from transume.draft import image_fingerprint  # noqa: E402
from transume.image_explorer import ExplorerRequest, ExplorerResult  # noqa: E402
from transume.client import run_explorer_request  # noqa: E402
from transume.protocol import PROTOCOL_VERSION, read_message, write_message  # noqa: E402


def direct_request(request: ExplorerRequest, caller_uid: int) -> ExplorerResult:
    environment = dict(os.environ, PKEXEC_UID=str(caller_uid))
    process = subprocess.Popen(
        ["/usr/lib/transume/transume-runner", "mount", "--stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, start_new_session=True,
    )
    assert process.stdin is not None and process.stdout is not None
    write_message(process.stdin, {"type": "hello", "version": PROTOCOL_VERSION})
    if read_message(process.stdout)["type"] != "hello":
        raise RuntimeError("runner handshake failed")
    write_message(process.stdin, {
        "type": "explorer-request", "version": PROTOCOL_VERSION,
        "request": request.to_dict(),
    })
    process.stdin.close()
    value = read_message(process.stdout)
    returncode = process.wait(timeout=180)
    if value["type"] != "explorer-result" or returncode != (0 if value["status"] in {"ok", "not-mounted"} else 1):
        raise RuntimeError("runner returned an invalid explorer result")
    return ExplorerResult(value["request_id"], value["status"], value["detail"], value.get("session_id"), value.get("mountpoint"))

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True); parser.add_argument("--image", required=True)
    parser.add_argument("--partition", required=True); parser.add_argument("--file", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--caller-uid", type=int)
    parser.add_argument("--test-busy", action="store_true")
    parser.add_argument("--test-crash-recovery", action="store_true")
    args = parser.parse_args()
    def request(value: ExplorerRequest) -> ExplorerResult:
        return direct_request(value, args.caller_uid) if args.caller_uid is not None else run_explorer_request(value)
    image = Path(args.repository) / args.image
    result = request(ExplorerRequest("vmexplore", "connect", str(Path(args.repository).resolve()), args.image, image_fingerprint(image), args.partition))
    if result.status != "ok" or not result.mountpoint or not result.session_id: raise RuntimeError(result.detail)
    state_path = Path("/run/transume/explorer") / f"{result.session_id}.json"
    state = json.loads(state_path.read_text(encoding="ascii")) if os.geteuid() == 0 else None
    busy_process = None
    try:
        current = request(ExplorerRequest("vmexplore-status", "status", session_id=result.session_id))
        if current.status != "ok" or current.mountpoint != result.mountpoint:
            raise RuntimeError(f"explorer status failed: {current.detail}")
        mount = next(line for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines() if line.split()[4] == result.mountpoint)
        fields = mount.split(); separator = fields.index("-")
        options = set(fields[5].split(",")) | set(fields[separator + 3].split(","))
        if not {"ro", "nosuid", "nodev", "noexec"} <= options: raise RuntimeError("explorer mount options are unsafe")
        source = subprocess.run(["/usr/bin/findmnt", "-n", "-o", "SOURCE", "--target", result.mountpoint], capture_output=True, text=True, check=False).stdout.strip()
        if not source.startswith("/dev/nbd") or subprocess.run(["/usr/sbin/blockdev", "--getro", source], capture_output=True, text=True, check=False).stdout.strip() != "1": raise RuntimeError("explorer block device is writable")
        fixture = Path(result.mountpoint, args.file)
        if hashlib.sha256(fixture.read_bytes()).hexdigest() != args.sha256: raise RuntimeError("fixture hash mismatch")
        if args.caller_uid is not None:
            caller = pwd.getpwuid(args.caller_uid).pw_name
            caller_hash = subprocess.run(
                ["/usr/sbin/runuser", "-u", caller, "--", "/usr/bin/sha256sum", str(fixture)],
                capture_output=True, text=True, check=True,
            ).stdout.split()[0]
            if caller_hash != args.sha256:
                raise RuntimeError("caller cannot read explorer fixture")
            denied = subprocess.run(
                ["/usr/sbin/runuser", "-u", "nobody", "--", "/usr/bin/test", "-r", str(fixture)],
                check=False,
            )
            if denied.returncode == 0:
                raise RuntimeError("unrelated user can read explorer fixture")
        if args.test_crash_recovery:
            assert state is not None
            os.killpg(state["pids"][0]["pid"], signal.SIGKILL)
            time.sleep(1)
            stale = request(ExplorerRequest("vmexplore-stale", "status", session_id=result.session_id))
            if stale.status != "failed" or "stale" not in stale.detail:
                raise RuntimeError("crashed explorer session was not reported stale")
            recovered = request(ExplorerRequest(
                "vmexplore-recover", "connect", str(Path(args.repository).resolve()),
                args.image, image_fingerprint(image), args.partition,
            ))
            if recovered.status != "ok" or not recovered.mountpoint or not recovered.session_id:
                raise RuntimeError(recovered.detail)
            if state_path.exists() or Path(result.mountpoint).exists():
                raise RuntimeError("stale explorer session was not recovered")
            recovered_state_path = Path("/run/transume/explorer") / f"{recovered.session_id}.json"
            recovered_state = json.loads(recovered_state_path.read_text(encoding="ascii"))
            if any(Path(f"/proc/{item['pid']}").exists() for item in state["pids"]):
                raise RuntimeError("stale explorer process remains")
            for device in state["nbds"]:
                sysfs = Path("/sys/class/block") / Path(device).name
                active = ((sysfs / "pid").exists()
                          or int((sysfs / "size").read_text(encoding="ascii")) != 0)
                if active and device not in recovered_state["nbds"]:
                    raise RuntimeError("stale explorer NBD association remains")
            result = recovered
            state_path = recovered_state_path
            state = recovered_state
        if args.test_busy:
            busy_process = subprocess.Popen(["/usr/bin/sleep", "60"], cwd=result.mountpoint)
            busy = request(ExplorerRequest("vmexplore-busy", "disconnect", session_id=result.session_id))
            if busy.status != "failed" or "busy" not in busy.detail or not state_path.exists():
                raise RuntimeError("busy explorer mount did not remain available for retry")
    finally:
        if busy_process is not None:
            busy_process.terminate()
            busy_process.wait(timeout=5)
        disconnected = request(ExplorerRequest("vmexplore-stop", "disconnect", session_id=result.session_id))
        if disconnected.status != "ok": raise RuntimeError(disconnected.detail)
    if state_path.exists() or Path(result.mountpoint).exists(): raise RuntimeError("explorer state remains")
    if state is not None:
        if any(Path(f"/proc/{item['pid']}").exists() for item in state["pids"]):
            raise RuntimeError("explorer process remains")
        for device in state["nbds"]:
            sysfs = Path("/sys/class/block") / Path(device).name
            if (sysfs / "pid").exists() or int((sysfs / "size").read_text(encoding="ascii")) != 0:
                raise RuntimeError("explorer NBD association remains")
    return 0
if __name__ == "__main__": raise SystemExit(main())
