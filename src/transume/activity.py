"""Private, redacted per-job activity logs."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path


MAX_LINE = 8192
MAX_SIZE = 10 * 1024 * 1024
_SECRET = re.compile(r"(?i)\b(?:credential|passphrase|password|token|secret|apikey|api_key)\s*(?:=|:|\s)\s*[^\s&]+")
_QUERY = re.compile(r"([?&](?:password|passphrase|token|secret|credential)=[^&#\s]+)", re.I)


def redact(value: str) -> str:
    return _QUERY.sub(lambda match: match.group(1).split("=", 1)[0] + "=***", _SECRET.sub("[REDACTED]", value))


class LogStore:
    """Append normalized public runner events to a user-owned regular file."""

    def __init__(self, job_id: str, *, root: Path) -> None:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", job_id):
            raise ValueError("invalid log job id")
        self.root = root
        self.path = root / f"{job_id}.log"
        self._stream = None
        self._size = 0
        self._truncated = False
        self._open()

    def _open(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("unsafe log directory")
        os.chmod(self.root, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            os.close(fd)
            raise ValueError("unsafe log file")
        os.fchmod(fd, 0o600)
        self._size = info.st_size
        self._stream = os.fdopen(fd, "a", encoding="utf-8", errors="replace")

    def append(self, event: dict) -> None:
        if self._stream is None or self._truncated:
            return
        kind = event.get("kind", event.get("level", "log"))
        message = redact(str(event.get("message", "")).replace("\r", "").replace("\n", " "))
        line = f"[{kind}] {message}"
        if len(line) > MAX_LINE:
            line = line[:MAX_LINE - 20] + " [line truncated]"
        encoded = (line + "\n").encode("utf-8")
        marker = b"[log truncated: size limit reached]\n"
        # Keep room for an explicit marker rather than silently dropping the final event.
        if self._size + len(encoded) > MAX_SIZE - len(marker):
            if self._size + len(marker) <= MAX_SIZE:
                self._stream.buffer.write(marker)
                self._size += len(marker)
            self._truncated = True
            return
        self._stream.buffer.write(encoded)
        self._size += len(encoded)

    def close(self) -> None:
        if self._stream is not None:
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
            self._stream = None
