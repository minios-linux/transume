"""Mutable, unprivileged job planning state.

Secrets deliberately do not belong here: this object is safe to inspect for a
review screen, but is never sent to the privileged runner.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .images import ImageCandidate


@dataclass(slots=True)
class BackupOptions:
    compression: str = "zstd"
    engine: str = "partclone"
    verify_image: bool = True
    rescue: bool = False
    filesystem_check: str = "check"
    checksum: str = "none"
    image_size: int = 0  # Zero means Clonezilla's automatic split size.
    encrypt: bool = False
    post_action: str = "none"


@dataclass(slots=True)
class RestoreOptions:
    check_image: bool = True
    resize: bool = False
    restore_mbr: bool = True
    partition_table: str = "original"
    restore_ebr: bool = True
    hidden_data: bool = False
    update_efi: bool = True
    encrypted: bool = False
    source_partition: str = ""
    post_action: str = "none"


@dataclass(slots=True)
class CloneOptions:
    resize: bool = False
    rescue: bool = False
    force_dd: bool = False
    hidden_data: bool = False
    direct_io: bool = False
    post_action: str = "none"


@dataclass(frozen=True, slots=True)
class ImagePreflightContext:
    """Non-secret selection evidence; never serialized in PublicJobSpec."""
    path: Path
    fingerprint: str


@dataclass(slots=True)
class JobDraft:
    operation: str
    source: Any = None
    destination: Any = None
    destinations: list[Any] = field(default_factory=list)
    repository: Path | None = None
    image_name: str | None = None
    options: BackupOptions | RestoreOptions | CloneOptions | None = None
    image_context: ImagePreflightContext | None = None
    validation_issues: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.options is None:
            self.options = {"backup": BackupOptions, "restore": RestoreOptions,
                            "clone": CloneOptions}.get(self.operation, lambda: None)()

    def set_source(self, value: Any) -> None:
        self.source = value
        if self.operation == "restore" and isinstance(value, ImageCandidate):
            self.image_context = ImagePreflightContext(value.path, image_fingerprint(value.path))

    def set_destination(self, value: Any) -> None:
        self.destination = value
        self.destinations = [value] if value is not None else []

    def set_destinations(self, values: list[Any]) -> None:
        self.destinations = list(values)
        self.destination = values[0] if len(values) == 1 else None

    def option_values(self) -> dict[str, str | bool | int]:
        if self.options is None:
            return {}
        return dict(asdict(self.options))

    def summary(self) -> str:
        targets = self.destinations or ([self.destination] if self.destination else [])
        return f"{self.operation}: {getattr(self.source, 'name', self.source) or 'source'} -> {len(targets)} target(s)"


def image_fingerprint(path: Path) -> str:
    """Bounded, symlink-free image evidence suitable for the privilege boundary."""
    import hashlib
    digest = hashlib.sha256()
    root = path.resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("image path is unavailable")
    entries = 0
    # Clonezilla creates payloads as root mode 0600. Use ctime in the bounded
    # manifest: unlike mtime it cannot be restored by an unprivileged writer after
    # changing content, and the desktop process never needs payload read access.
    for parent, directories, files in __import__("os").walk(root, followlinks=False):
        names = sorted([*directories, *files])
        for name in names:
            entry = Path(parent) / name
            info = entry.lstat()
            entries += 1
            if entries > 4096 or entry.is_symlink():
                raise ValueError("image evidence is unavailable")
            relative = entry.relative_to(root)
            digest.update(
                f"{relative}\0{info.st_mode}\0{info.st_size}\0{info.st_mtime_ns}\0"
                f"{info.st_ctime_ns}\0{info.st_ino}\n".encode()
            )
    return digest.hexdigest()
