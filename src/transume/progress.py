"""Conservative parsing of Clonezilla, Partclone, and pv progress output."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass


_PERCENT = re.compile(r"(?<![\d.])(?P<percent>\d{1,3}(?:\.\d+)?)%")
_PARTCLONE = re.compile(
    r"(?:Elapsed|elapsed).*?(?P<percent>\d{1,3}(?:\.\d+)?)%.*?"
    r"(?:Rate|rate)[: ]+(?P<rate>[^,]+)", re.IGNORECASE,
)
_DEVICE = re.compile(r"(?:/dev/)?(?P<device>(?:sd|hd|vd|xvd)[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?)")
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_NON_FATAL_WARNINGS = ("unrecognised disk label", "unrecognized disk label")
_LIVE_MEDIA_WARNING = "filesystem.squashfs not found"


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    kind: str
    message: str
    percent: float | None = None
    device: str | None = None
    rate: str | None = None


class ProgressParser:
    def __init__(self) -> None:
        self._last_percent: float | None = None

    def feed_line(self, line: str) -> ProgressEvent:
        clean = _ANSI.sub("", line).replace("\r", "").strip()
        lowered = clean.casefold()
        device_match = _DEVICE.search(clean)
        device = device_match.group("device") if device_match else None
        partclone = _PARTCLONE.search(clean)
        if partclone:
            percent = _valid_percent(partclone.group("percent"))
            self._last_percent = percent
            return ProgressEvent("progress", clean, percent, device, partclone.group("rate").strip())
        percent_match = _PERCENT.search(clean)
        if percent_match:
            percent = _valid_percent(percent_match.group("percent"))
            self._last_percent = percent
            return ProgressEvent("progress", clean, percent, device)
        if any(message in lowered for message in _NON_FATAL_WARNINGS):
            return ProgressEvent("warning", clean, self._last_percent, device)
        if _LIVE_MEDIA_WARNING in lowered:
            return ProgressEvent(
                "log",
                "Running in the MiniOS live environment.",
                self._last_percent,
                device,
            )
        if re.search(r"\b(?:error|failed|failure|fatal)\b", lowered):
            return ProgressEvent("error", clean, self._last_percent, device)
        if any(word in lowered for word in ("warning", "warn:")):
            return ProgressEvent("warning", clean, self._last_percent, device)
        if any(word in lowered for word in ("saving", "restoring", "checking", "cloning", "creating partition")):
            return ProgressEvent("stage", clean, self._last_percent, device)
        return ProgressEvent("log", clean, self._last_percent, device)


def _valid_percent(value: str) -> float:
    percent = float(value)
    if not 0 <= percent <= 100:
        raise ValueError("progress percentage is outside 0..100")
    return percent


def elapsed_and_eta(samples: list[tuple[float, float]], now: float | None = None) -> tuple[float, float | None]:
    """Return elapsed time and ETA only for increasing monotonic progress samples."""
    if not samples:
        return 0.0, None
    now = time.monotonic() if now is None else now
    elapsed = max(0.0, now - samples[0][0])
    first, last = samples[0], samples[-1]
    if len(samples) < 2 or last[1] <= first[1] or last[1] >= 100 or last[0] <= first[0]:
        return elapsed, None
    rate = (last[1] - first[1]) / (last[0] - first[0])
    return elapsed, (100 - last[1]) / rate if rate > 0 else None
