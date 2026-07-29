"""Strict 32-bit length-prefixed UTF-8 JSON protocol."""

from __future__ import annotations

import json
import re
import struct
from typing import Any, BinaryIO, Mapping

PROTOCOL_VERSION = 2
MAX_MESSAGE_SIZE = 1024 * 1024
MAX_LOG_MESSAGE_SIZE = 64 * 1024
MAX_SECRET_LENGTH = 4096
RESULT_ERROR_CODES = frozenset({
    "validation-failed", "authorization-failed", "job-lock-active",
    "lock-metadata-unavailable", "mount-namespace-unavailable",
    "resource-journal-unavailable", "resource-recovery-failed", "clonezilla-failed",
    "clonezilla-reported-error", "cancelled", "request-failed",
})
STORAGE_ERROR_CODES = frozenset({
    "authentication-failed", "host-unreachable", "resource-not-found",
    "protocol-mismatch", "timeout", "host-key-changed", "target-busy",
    "operation-failed",
})
_SCHEMAS = {
    "hello": {"type", "version"},
    "job": {"type", "version", "spec"},
    "secret": {"type", "version", "value"},
    "storage-request": {"type", "version", "request"},
    "storage-result": {"type", "version", "request_id", "status", "root", "detail", "error_code"},
    "explorer-request": {"type", "version", "request"},
    "explorer-result": {"type", "version", "request_id", "status", "root", "detail", "session_id", "mountpoint"},
    "cancel": {"type", "version"},
    "result": {"type", "version", "status", "detail", "error_code", "exit_code", "verification", "cleanup"},
    "log": {"type", "version", "level", "message"},
    "progress": {"type", "version", "kind", "message", "percent", "device", "rate"},
}
_SECRET_TEXT = re.compile(r"(?i)\b(password|passphrase|token|secret|private[_ -]?key)\b\s*([=:])\s*[^\s,;]+")


def redact_text(value: str, *, secrets: tuple[str, ...] = ()) -> str:
    """Redact both labelled values and known transient secret values at IPC edges."""
    result = _SECRET_TEXT.sub(lambda match: f"{match.group(1)}{match.group(2)}***", value)
    for secret in secrets:
        if isinstance(secret, str) and secret:
            result = result.replace(secret, "***")
    return result[:MAX_LOG_MESSAGE_SIZE]


def encode_message(message: Mapping[str, Any]) -> bytes:
    validated = validate_message(message)
    payload = json.dumps(validated, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    limit = MAX_LOG_MESSAGE_SIZE if validated["type"] == "log" else MAX_MESSAGE_SIZE
    if len(payload) > limit:
        raise ValueError("message is too large")
    return struct.pack("!I", len(payload)) + payload


def decode_frame(frame: bytes) -> dict[str, Any]:
    if len(frame) < 4:
        raise ValueError("incomplete frame")
    size = struct.unpack("!I", frame[:4])[0]
    if size > MAX_MESSAGE_SIZE or size != len(frame) - 4:
        raise ValueError("invalid frame size")
    try:
        value = json.loads(frame[4:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON payload") from exc
    return validate_message(value)


def read_message(stream: BinaryIO) -> dict[str, Any]:
    header = _read_exact(stream, 4)
    size = struct.unpack("!I", header)[0]
    if size > MAX_MESSAGE_SIZE:
        raise ValueError("message is too large")
    return decode_frame(header + _read_exact(stream, size))


def write_message(stream: BinaryIO, message: Mapping[str, Any]) -> None:
    stream.write(encode_message(message))
    stream.flush()


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            raise EOFError("unexpected EOF")
        chunks.extend(chunk)
    return bytes(chunks)


def validate_message(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        raise ValueError("message must be an object with a type")
    expected = _SCHEMAS.get(value["type"])
    if expected is None or set(value) != expected:
        raise ValueError("unknown message type or fields")
    if value.get("version") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if value["type"] == "cancel":
        # The exact schema check above deliberately makes cancellation unambiguous.
        return dict(value)
    if value["type"] == "job" and not isinstance(value["spec"], dict):
        raise ValueError("invalid job message")
    if value["type"] == "secret":
        secret = value["value"]
        if (not isinstance(secret, str) or not secret or len(secret) > MAX_SECRET_LENGTH
                or any(character in secret for character in "\x00\r\n")):
            raise ValueError("invalid secret message")
    if value["type"] in {"storage-request", "explorer-request"} and not isinstance(value["request"], dict):
        raise ValueError("invalid request message")
    if value["type"] == "storage-result":
        if (not isinstance(value["request_id"], str) or not isinstance(value["status"], str)
                or value["status"] not in {"ok", "failed", "not-mounted"}
                or value["root"] is not None and not isinstance(value["root"], str)
                or value["error_code"] is not None and value["error_code"] not in STORAGE_ERROR_CODES
                or not isinstance(value["detail"], str)):
            raise ValueError("invalid storage result message")
    if value["type"] == "explorer-result":
        if (not isinstance(value["request_id"], str) or not isinstance(value["status"], str)
                or value["status"] not in {"ok", "failed", "not-mounted"}
                or value["root"] is not None
                or value["session_id"] is not None and not isinstance(value["session_id"], str)
                or value["mountpoint"] is not None and not isinstance(value["mountpoint"], str)
                or not isinstance(value["detail"], str)):
            raise ValueError("invalid explorer result message")
    if value["type"] == "log" and (value["level"] not in {"debug", "info", "warning", "error"} or not isinstance(value["message"], str)):
        raise ValueError("invalid log message")
    if value["type"] == "result":
        if (value["status"] not in {"dry-run", "ok", "failed", "cancelled"}
                or not isinstance(value["detail"], str)
                or value["error_code"] is not None and (
                    not isinstance(value["error_code"], str)
                    or value["error_code"] not in RESULT_ERROR_CODES)
                or value["exit_code"] is not None and (not isinstance(value["exit_code"], int) or isinstance(value["exit_code"], bool))
                or value["verification"] is not None and value["verification"] not in {"passed", "failed", "not-run"}
                or value["cleanup"] is not None and value["cleanup"] not in {"complete", "failed", "not-needed"}):
            raise ValueError("invalid result message")
    if value["type"] == "progress":
        if value["kind"] not in {"progress", "stage", "warning", "error", "log"}:
            raise ValueError("invalid progress kind")
        if not isinstance(value["message"], str):
            raise ValueError("invalid progress message")
        if value["percent"] is not None and (not isinstance(value["percent"], (int, float)) or isinstance(value["percent"], bool) or not 0 <= value["percent"] <= 100):
            raise ValueError("invalid progress percentage")
        if value["device"] is not None and not isinstance(value["device"], str):
            raise ValueError("invalid progress device")
        if value["rate"] is not None and not isinstance(value["rate"], str):
            raise ValueError("invalid progress rate")
    return dict(value)
