"""One-shot client for the PolicyKit-authorized runner."""

from __future__ import annotations

import shutil
import subprocess
import queue
import threading
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .domain import JobOperation, PublicJobSpec
from .protocol import MAX_SECRET_LENGTH, PROTOCOL_VERSION, read_message, write_message
from .storage import StorageRequest, StorageResult
from .image_explorer import ExplorerRequest, ExplorerResult


RUNNER = "/usr/lib/transume/transume-runner"


class AuthorizationError(RuntimeError):
    """PolicyKit did not authorize the one-shot privileged runner."""


@dataclass(frozen=True, slots=True)
class ClientResult:
    status: str
    detail: str
    events: tuple[dict, ...] = ()
    exit_code: int | None = None
    verification: str | None = None
    cleanup: str | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class ClientTimeouts:
    handshake: float = 15.0
    result: float = 12 * 60 * 60.0
    idle: float = 30 * 60.0
    shutdown: float = 10.0


@dataclass(slots=True)
class SecretValue:
    """Short-lived mutable passphrase storage, cleared after transport."""
    value: bytearray

    @classmethod
    def from_text(cls, value: str) -> "SecretValue":
        if not isinstance(value, str):
            raise ValueError("passphrase must be text")
        return cls(bytearray(value.encode("utf-8")))

    def take(self) -> str:
        try:
            value = self.value.decode("utf-8")
        finally:
            self.value[:] = b"\0" * len(self.value)
            self.value.clear()
        if (not value or len(value) > MAX_SECRET_LENGTH
                or any(character in value for character in "\x00\r\n")):
            raise ValueError("invalid passphrase")
        return value


def policy_action(spec: PublicJobSpec) -> str:
    if spec.operation is JobOperation.CHECK_IMAGE:
        return "check"
    return "write"


def run_spec(spec: PublicJobSpec, *, dry_run: bool = False,
               on_event: Callable[[dict], None] | None = None,
               cancel_event: threading.Event | None = None,
               secret: SecretValue | None = None, passphrase: str | None = None,
               popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
               timeouts: ClientTimeouts = ClientTimeouts()) -> ClientResult:
    needs_secret = ((spec.operation in {JobOperation.SAVEDISK, JobOperation.SAVEPARTS}
                     and spec.options.get("encrypt") is True)
                    or (spec.operation in {JobOperation.RESTOREDISK, JobOperation.RESTOREPARTS}
                        and spec.options.get("encrypted") is True))
    if secret is not None and passphrase is not None:
        raise ValueError("provide either secret or passphrase")
    if passphrase is not None:
        secret = SecretValue.from_text(passphrase)
    if needs_secret and not dry_run and secret is None:
        raise ValueError("an encryption passphrase is required")
    if not needs_secret and secret is not None:
        secret.take()
        raise ValueError("this job does not accept a passphrase")
    action = policy_action(spec)
    source_runner = Path(__file__).resolve().parents[2] / "bin" / "transume-runner"
    runner = str(source_runner) if dry_run and source_runner.is_file() else RUNNER
    command = [runner, action, "--stdio"]
    if dry_run:
        command.append("--dry-run")
    else:
        pkexec = shutil.which("pkexec")
        if pkexec is None:
            raise RuntimeError("PolicyKit pkexec is not installed")
        command.insert(0, pkexec)
    process = popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise RuntimeError("failed to create runner protocol pipes")
    messages: queue.Queue[dict | BaseException] = queue.Queue()

    def read_output() -> None:
        try:
            while True:
                messages.put(read_message(process.stdout))
        except (EOFError, ValueError) as error:
            messages.put(error)

    reader = threading.Thread(target=read_output, name="transume-runner-reader", daemon=True)
    reader.start()
    cancel_sent = False
    job_sent = False
    started = time.monotonic()
    last_event = started

    def next_message(deadline: float) -> dict:
        nonlocal cancel_sent, last_event
        while True:
            now = time.monotonic()
            if now >= deadline or (job_sent and now - last_event >= timeouts.idle):
                raise TimeoutError("privileged runner timed out")
            if job_sent and cancel_event is not None and cancel_event.is_set() and not cancel_sent:
                write_message(process.stdin, {"type": "cancel", "version": PROTOCOL_VERSION})
                cancel_sent = True
            try:
                message = messages.get(timeout=0.1)
            except queue.Empty:
                continue
            if isinstance(message, BaseException):
                raise message
            last_event = time.monotonic()
            return message

    try:
        write_message(process.stdin, {"type": "hello", "version": PROTOCOL_VERSION})
        response = next_message(started + timeouts.handshake)
        if response["type"] != "hello":
            raise RuntimeError("runner handshake failed")
        write_message(process.stdin, {
            "type": "job", "version": PROTOCOL_VERSION, "spec": spec.to_dict(),
        })
        job_sent = True
        if needs_secret and not dry_run:
            assert secret is not None
            value = secret.take()
            try:
                write_message(process.stdin, {"type": "secret", "version": PROTOCOL_VERSION,
                                              "value": value})
            finally:
                # `value` is necessarily an immutable transient for JSON encoding.
                value = ""
        events = []
        while True:
            result = next_message(started + timeouts.result)
            if result["type"] == "result":
                return ClientResult(result["status"], result["detail"], tuple(events),
                                     result["exit_code"], result["verification"], result["cleanup"],
                                     result["error_code"])
            if result["type"] not in {"progress", "log"}:
                raise RuntimeError("runner returned an unexpected message")
            events.append(result)
            if on_event is not None:
                on_event(result)
    except Exception as error:
        if process.poll() is None:
            _stop_process_group(process, timeouts.shutdown)
        stderr = (
            process.stderr.read().decode("utf-8", "replace").strip()
            if process.stderr is not None else ""
        )
        detail = stderr or str(error)
        if process.returncode in {126, 127} and any(value in detail.casefold() for value in (
            "not authorized", "authorization failed", "authentication cancelled",
        )):
            raise AuthorizationError("authorization was cancelled or denied") from error
        raise RuntimeError(
            f"privileged runner exited with status {process.returncode}: {detail}"
        ) from error
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            try:
                process.wait(timeout=timeouts.shutdown)
            except subprocess.TimeoutExpired:
                _stop_process_group(process, timeouts.shutdown)


def _stop_process_group(process, timeout: float) -> None:
    """The runner owns a session, so stalled descendants cannot retain its pipes."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (AttributeError, ProcessLookupError):
        try: process.terminate()
        except (AttributeError, ProcessLookupError): pass
    try:
        process.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError):
        try: process.kill()
        except (AttributeError, ProcessLookupError): pass
    process.wait(timeout=timeout)


def run_storage_request(request: StorageRequest, *, dry_run: bool = False,
                        popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
                        timeouts: ClientTimeouts = ClientTimeouts()) -> StorageResult:
    """Send private credentials solely through the framed stdin pipe to `mount`."""
    source_runner = Path(__file__).resolve().parents[2] / "bin" / "transume-runner"
    runner = str(source_runner) if dry_run and source_runner.is_file() else RUNNER
    command = [runner, "mount", "--stdio"]
    if dry_run:
        command.append("--dry-run")
    else:
        pkexec = shutil.which("pkexec")
        if pkexec is None:
            raise RuntimeError("PolicyKit pkexec is not installed")
        command.insert(0, pkexec)
    process = popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    start_new_session=True)
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise RuntimeError("failed to create runner protocol pipes")
    try:
        write_message(process.stdin, {"type": "hello", "version": PROTOCOL_VERSION})
        if _read_with_timeout(process.stdout, timeouts.handshake)["type"] != "hello":
            raise RuntimeError("runner handshake failed")
        write_message(process.stdin, {"type": "storage-request", "version": PROTOCOL_VERSION,
                                      "request": request.to_dict()})
        result = _read_with_timeout(process.stdout, timeouts.result)
        if result["type"] != "storage-result" or result["request_id"] != request.request_id:
            raise RuntimeError("runner returned an unexpected message")
        return StorageResult(result["request_id"], result["status"], result["root"],
                             result["detail"], result["error_code"])
    finally:
        process.stdin.close()
        if process.poll() is None:
            try:
                process.wait(timeout=timeouts.shutdown)
            except subprocess.TimeoutExpired:
                _stop_process_group(process, timeouts.shutdown)


def run_explorer_request(request: ExplorerRequest, *, dry_run: bool = False,
                         popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
                         timeouts: ClientTimeouts = ClientTimeouts()) -> ExplorerResult:
    """Use the mount PolicyKit action, with a distinct frame namespace."""
    source_runner = Path(__file__).resolve().parents[2] / "bin" / "transume-runner"
    command = [str(source_runner) if dry_run and source_runner.is_file() else RUNNER, "mount", "--stdio"]
    if dry_run: command.append("--dry-run")
    else:
        pkexec = shutil.which("pkexec")
        if pkexec is None: raise RuntimeError("PolicyKit pkexec is not installed")
        command.insert(0, pkexec)
    process = popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    if process.stdin is None or process.stdout is None:
        process.kill(); raise RuntimeError("failed to create runner protocol pipes")
    try:
        write_message(process.stdin, {"type": "hello", "version": PROTOCOL_VERSION})
        if _read_with_timeout(process.stdout, timeouts.handshake)["type"] != "hello": raise RuntimeError("runner handshake failed")
        write_message(process.stdin, {"type": "explorer-request", "version": PROTOCOL_VERSION, "request": request.to_dict()})
        result = _read_with_timeout(process.stdout, min(timeouts.result, 600.0))
        if result["type"] != "explorer-result" or result["request_id"] != request.request_id: raise RuntimeError("runner returned an unexpected message")
        return ExplorerResult(result["request_id"], result["status"], result["detail"], result.get("session_id"), result.get("mountpoint"))
    finally:
        process.stdin.close()
        if process.poll() is None:
            try: process.wait(timeout=timeouts.shutdown)
            except subprocess.TimeoutExpired: _stop_process_group(process, timeouts.shutdown)


class ImageExplorerClient:
    """Small UI adapter matching StorageManager's one-shot privileged boundary."""
    def __init__(self, execute: Callable[[ExplorerRequest], ExplorerResult] = run_explorer_request) -> None: self.execute = execute
    def connect(self, request: ExplorerRequest) -> ExplorerResult:
        if request.operation != "connect": raise ValueError("connect request required")
        return self.execute(request)
    def disconnect(self, request_id: str, session_id: str) -> ExplorerResult:
        return self.execute(ExplorerRequest(request_id, "disconnect", session_id=session_id))
    def status(self, request_id: str, session_id: str) -> ExplorerResult:
        return self.execute(ExplorerRequest(request_id, "status", session_id=session_id))


def _read_with_timeout(stream, timeout: float) -> dict:
    received: queue.Queue[dict | BaseException] = queue.Queue(maxsize=1)
    def read() -> None:
        try: received.put(read_message(stream))
        except (EOFError, ValueError) as error: received.put(error)
    threading.Thread(target=read, name="transume-protocol-reader", daemon=True).start()
    try:
        value = received.get(timeout=timeout)
    except queue.Empty as exc:
        raise TimeoutError("privileged runner timed out") from exc
    if isinstance(value, BaseException):
        raise value
    return value
