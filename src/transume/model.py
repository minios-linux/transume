"""Unprivileged application model used by the GTK frontend."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterable
from uuid import uuid4

from .capabilities import ClonezillaCapabilities, probe_clonezilla
from .catalog import CatalogLocation, ImageCatalog
from .images import ImageCandidate, ImageStatus
from .inventory import BlockDevice, scan_block_devices
from .domain import DeviceIdentity
from .storage import StorageKind, StorageLocation
from .filesystem import rename_noreplace


class ImageMutationError(ValueError):
    """A user-presentable mutation failure, optionally with a recovery location."""

    def __init__(self, code: str, message: str, recovery_path: Path | None = None) -> None:
        super().__init__(message)
        self.code, self.recovery_path = code, recovery_path


_IMAGE_NAME = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def format_size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if size < 1024 or unit == "PiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


@dataclass(frozen=True, slots=True)
class DeviceItem:
    name: str
    path: str
    size: str
    selectable_source: bool
    selectable_destination: bool
    status: str
    identity: DeviceIdentity | None = None


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    name: str
    mac: str
    state: str


@dataclass(frozen=True, slots=True)
class ActivityRecord:
    job_id: str
    operation: str
    started_at: datetime
    finished_at: datetime | None
    status: str | None
    source_label: str
    destination_label: str
    detail: str
    progress_summary: str | None = None
    log_summary: str | None = None
    exit_code: int | None = None
    verification: str | None = None
    cleanup: str | None = None
    log_path: str | None = None
    affected_labels: tuple[str, ...] = ()


_ACTIVITY_VERSION = 2
_ACTIVITY_LIMIT = 100


class ApplicationModel:
    def __init__(self, *, catalog_path: Path | None = None,
                 activity_path: Path | None = None) -> None:
        self.repository: Path | None = None
        state_root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        state_dir = state_root / "transume"
        self.activity_path = activity_path or state_dir / "activity.json"
        self.log_dir = self.activity_path.parent / "logs"
        self._activity: list[ActivityRecord] = self._load_activity()
        self.capabilities: ClonezillaCapabilities | None = None
        self.catalog = ImageCatalog(
            catalog_path or state_dir / "catalog.json"
        )
        self._repository_location_id: str | None = None
        self._active_image_jobs: dict[str, tuple[str, str]] = {}

    def discover(self) -> ClonezillaCapabilities:
        self.capabilities = probe_clonezilla()
        return self.capabilities

    def list_devices(self) -> list[DeviceItem]:
        return [
            self._device_item(item)
            for item in scan_block_devices()
            if item.device_type not in {"loop", "rom", "zram", "ram"}
            and not Path(item.path).name.startswith("zram")
        ]

    def _device_item(self, item: BlockDevice) -> DeviceItem:
        flags = []
        if item.is_system:
            flags.append("System")
        if item.is_live:
            flags.append("Live media")
        if item.is_mounted:
            flags.append("Mounted")
        if item.read_only:
            flags.append("Read-only")
        identity = self._identity_or_none(item)
        if identity is None:
            flags.append("No stable identity")
        return DeviceItem(
            name=(item.model or item.name).strip(),
            path=item.path,
            size=format_size(item.size),
            selectable_source=item.selectable_source and identity is not None,
            selectable_destination=item.selectable_destination and identity is not None,
            status=", ".join(flags) or "Available",
            identity=identity,
        )

    @staticmethod
    def _identity_or_none(item: BlockDevice) -> DeviceIdentity | None:
        try:
            return item.identity()
        except ValueError:
            return None

    def set_repository(self, path: Path) -> None:
        resolved = path.expanduser().resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError("storage folder must be a directory")
        self.set_storage_location(StorageLocation(StorageKind.LOCAL_FOLDER, str(resolved)))

    def set_storage_location(self, location: StorageLocation) -> None:
        """Use a mounted or user-authorized location without retaining credentials."""
        root = Path(location.root).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("storage location must be a directory")
        # The mount root changes per session, while the endpoint identifies the location.
        identity = "\x1f".join((location.kind.value, location.host or "", location.share or "",
                                  location.endpoint or "", location.device or "",
                                  location.username or "", str(location.port or ""),
                                  str(root) if location.kind is StorageKind.LOCAL_FOLDER else ""))
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        location_id = f"{location.kind.value}-{digest}"
        self.repository = root
        self.catalog.add_location(location_id, location)
        self._repository_location_id = location_id

    def clear_current_location(self) -> None:
        """Release the live root while retaining credential-free catalog history."""
        if (self.repository is not None and self._repository_location_id is not None
                and str(self.repository).startswith("/run/")):
            self.catalog.mark_location_unavailable(self._repository_location_id)
        self.repository = None
        self._repository_location_id = None

    def recent_locations(self) -> tuple[CatalogLocation, ...]:
        return tuple(CatalogLocation(location_id, location)
                     for location_id, location in self.catalog.locations.items())

    def list_images(self) -> list[ImageCandidate]:
        if self.repository is None or self._repository_location_id is None:
            return []
        result = self.catalog.refresh(
            self._repository_location_id, self.repository, recursive_depth=0,
        )
        return sorted(result.candidates, key=lambda image: image.name.casefold())

    def list_network_interfaces(self) -> list[NetworkInterface]:
        """Return usable interfaces without requiring iproute2 or NetworkManager."""
        root = Path("/sys/class/net")
        try:
            entries = sorted(root.iterdir(), key=lambda entry: entry.name)
        except OSError:
            return []
        result = []
        for entry in entries:
            if entry.name == "lo":
                continue
            try:
                mac = (entry / "address").read_text(encoding="ascii").strip()
                state = (entry / "operstate").read_text(encoding="ascii").strip()
            except OSError:
                continue
            result.append(NetworkInterface(entry.name, mac, state))
        return result

    def list_activity(self) -> Iterable[ActivityRecord]:
        return tuple(self._activity)

    def start_activity(self, operation: str, spec: object) -> str:
        """Create the record from the GTK main-thread job start callback."""
        sources = getattr(spec, "sources", ())
        destinations = getattr(spec, "destinations", ())
        job_id = str(uuid4())
        source = _safe_label(sources, getattr(spec, "image_name", None) or "Source")
        destination = _safe_label(destinations, _repository_label(getattr(spec, "repository", None)) or "Destination")
        record = ActivityRecord(job_id, operation, _utcnow(), None, None, source, destination,
                                "Operation started", log_path=str(self.log_dir / f"{job_id}.log"),
                                affected_labels=tuple(dict.fromkeys((source, destination))))
        self._activity.append(record)
        repository, image_name = getattr(spec, "repository", None), getattr(spec, "image_name", None)
        if isinstance(repository, str) and isinstance(image_name, str):
            self._active_image_jobs[record.job_id] = (repository, image_name)
        evicted = self._activity[:-_ACTIVITY_LIMIT]
        self._activity = self._activity[-_ACTIVITY_LIMIT:]
        for old in evicted:
            self._delete_log(old.log_path)
        self._save_activity()
        return record.job_id

    def finish_activity(self, job_id: str, status: str, detail: str,
                         *, progress_summary: str | None = None,
                         log_summary: str | None = None, exit_code: int | None = None,
                         verification: str | None = None, cleanup: str | None = None) -> None:
        if status not in {"ok", "failed", "cancelled"}:
            status = "failed"
        for index, record in enumerate(self._activity):
            if record.job_id == job_id:
                self._activity[index] = ActivityRecord(
                    record.job_id, record.operation, record.started_at, _utcnow(), status,
                    record.source_label, record.destination_label, _safe_detail(status, detail),
                    _safe_summary(progress_summary), _safe_summary(log_summary),
                    exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None,
                    verification if verification in {"passed", "failed", "not-run"} else None,
                    cleanup if cleanup in {"complete", "failed", "not-needed"} else None,
                    record.log_path, record.affected_labels,
                )
                self._save_activity()
                self._active_image_jobs.pop(job_id, None)
                return

    def clear_activity(self) -> None:
        for record in self._activity:
            self._delete_log(record.log_path)
        self._activity = []
        self._save_activity()

    def log_path(self, record: ActivityRecord) -> Path | None:
        path = self._owned_log(record.log_path)
        if path is None:
            return None
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        return path if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid() else None

    def mark_verified(self, candidate: ImageCandidate) -> ImageCandidate:
        return self.catalog.mark_verified(candidate)

    def rename_image(self, candidate: ImageCandidate, new_name: str) -> ImageCandidate:
        if not _IMAGE_NAME.fullmatch(new_name):
            raise ImageMutationError("invalid-name", "New image name contains unsafe characters")
        source, root = self._current_image(candidate)
        if source.name == new_name:
            raise ImageMutationError("same-name", "New image name is unchanged")
        target = root / new_name
        if target.exists() or target.is_symlink():
            raise ImageMutationError("target-exists", "An image with that name already exists")
        try:
            rename_noreplace(source, target)
        except OSError as error:
            raise ImageMutationError("rename-failed", f"Image was not renamed: {error}") from error
        result = self._find_refreshed(target.name)
        self.catalog.clear_verification(candidate)
        return result

    def delete_image(self, candidate: ImageCandidate, confirmation: str) -> None:
        if confirmation != candidate.name:
            raise ImageMutationError("confirmation-required", "Type the exact image name to delete it")
        source, root = self._current_image(candidate, allow_malformed=True)
        trash = self._trash_directory(root)
        quarantined = trash / uuid4().hex
        try:
            rename_noreplace(source, quarantined)
        except OSError as error:
            raise ImageMutationError("quarantine-failed", f"Image was not moved to trash: {error}") from error
        try:
            _delete_quarantined_tree(quarantined)
        except OSError as error:
            self.list_images()
            raise ImageMutationError("delete-incomplete", "Deletion failed; the image remains quarantined for recovery", quarantined) from error
        self.list_images()
        self.catalog.clear_verification(candidate)

    def containing_folder_uri(self, candidate: ImageCandidate) -> str:
        source, _root = self._current_image(candidate, allow_malformed=True)
        return source.parent.as_uri()

    def _current_image(self, candidate: ImageCandidate, *, allow_malformed: bool = False) -> tuple[Path, Path]:
        if self.repository is None or self._repository_location_id is None:
            raise ImageMutationError("no-location", "Choose an image folder first")
        root = self.repository.resolve(strict=True)
        if self.repository.is_symlink() or not root.is_dir():
            raise ImageMutationError("unsafe-location", "Active image folder is not a real directory")
        fresh = self.list_images()
        found = next((item for item in fresh if item.location_id == candidate.location_id
                      and item.relative_id == candidate.relative_id and item.path == candidate.path), None)
        if found is None or found.location_id != self._repository_location_id:
            raise ImageMutationError("stale-image", "Image is no longer available in the active folder")
        if not allow_malformed and found.status not in {ImageStatus.READY, ImageStatus.NEEDS_VERIFICATION}:
            raise ImageMutationError("unusable-image", "Only available usable images can be renamed")
        if any(location == str(root) for location, _name in self._active_image_jobs.values()):
            raise ImageMutationError("job-active", "This image folder is in use by an active job")
        try:
            source = found.path.resolve(strict=True)
            source.relative_to(root)
        except (OSError, ValueError) as error:
            raise ImageMutationError("image-escape", "Image is outside the active folder or unavailable") from error
        try:
            info = found.path.lstat()
        except OSError as error:
            raise ImageMutationError("image-unavailable", "Image is unavailable") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or source.parent != root:
            raise ImageMutationError("unsafe-image", "Image must be a real directory directly inside the active folder")
        return source, root

    def _find_refreshed(self, name: str) -> ImageCandidate:
        found = next((item for item in self.list_images() if item.name == name), None)
        if found is None:
            raise ImageMutationError("refresh-failed", "Image changed but could not be refreshed")
        return found

    @staticmethod
    def _trash_directory(root: Path) -> Path:
        trash = root / ".transume-trash"
        try:
            trash.mkdir(mode=0o700)
        except FileExistsError:
            pass
        try:
            info = trash.lstat()
        except OSError as error:
            raise ImageMutationError("trash-unavailable", "Trash directory is unavailable") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or (stat.S_IMODE(info.st_mode) != 0o700):
            raise ImageMutationError("unsafe-trash", "Trash directory must be user-owned, real, and mode 0700")
        return trash

    def _load_activity(self) -> list[ActivityRecord]:
        if not self.activity_path.exists():
            return []
        try:
            with self.activity_path.open(encoding="utf-8") as stream:
                data = json.load(stream)
            version = data.get("version")
            if version not in {1, _ACTIVITY_VERSION} or not isinstance(data.get("records"), list):
                raise ValueError("unsupported activity history")
            records = []
            for item in data["records"][-_ACTIVITY_LIMIT:]:
                legacy = {"job_id", "operation", "started_at", "finished_at", "status", "source_label", "destination_label", "detail", "progress_summary", "log_summary"}
                current = legacy | {"exit_code", "verification", "cleanup", "log_path", "affected_labels"}
                if set(item) != (legacy if version == 1 else current):
                    raise ValueError("invalid activity record")
                status = item["status"]
                if status not in {None, "ok", "failed", "cancelled"}:
                    raise ValueError("invalid activity status")
                log_path = None if version == 1 else item["log_path"]
                if log_path is not None and self._owned_log(log_path) is None:
                    raise ValueError("unsafe activity log path")
                records.append(ActivityRecord(item["job_id"], item["operation"], datetime.fromisoformat(item["started_at"]), datetime.fromisoformat(item["finished_at"]) if item["finished_at"] else None, status, item["source_label"], item["destination_label"], item["detail"], item["progress_summary"], item["log_summary"], None if version == 1 else item["exit_code"], None if version == 1 else item["verification"], None if version == 1 else item["cleanup"], log_path, () if version == 1 else tuple(item["affected_labels"])))
            self._cleanup_orphan_logs(records)
            return records
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            quarantine = self.activity_path.with_name(f"{self.activity_path.name}.corrupt-{uuid4().hex}")
            try:
                os.replace(self.activity_path, quarantine)
            except OSError:
                pass
            return []

    def _owned_log(self, value: str | None) -> Path | None:
        if not isinstance(value, str):
            return None
        path = Path(value)
        try:
            path.relative_to(self.log_dir)
        except ValueError:
            return None
        return path if path.parent == self.log_dir and path.suffix == ".log" else None

    def _delete_log(self, value: str | None) -> None:
        path = self._owned_log(value)
        if path is None:
            return
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid():
                path.unlink()
        except FileNotFoundError:
            pass

    def _cleanup_orphan_logs(self, records: list[ActivityRecord]) -> None:
        try:
            entries = tuple(self.log_dir.iterdir())
        except OSError:
            return
        retained = {record.log_path for record in records}
        for path in entries:
            if str(path) not in retained:
                self._delete_log(str(path))

    def _save_activity(self) -> None:
        self.activity_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": _ACTIVITY_VERSION, "records": [{**asdict(record), "started_at": record.started_at.isoformat(), "finished_at": record.finished_at.isoformat() if record.finished_at else None} for record in self._activity[-_ACTIVITY_LIMIT:]]}
        fd, temporary = tempfile.mkstemp(prefix=f".{self.activity_path.name}.", dir=self.activity_path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = -1
                json.dump(data, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.activity_path)
            os.chmod(self.activity_path, 0o600)
        finally:
            if fd != -1:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_label(items: object, fallback: str) -> str:
    values = tuple(items) if isinstance(items, (tuple, list)) else ()
    if not values:
        return fallback
    value = values[0]
    path = getattr(value, "path", None)
    return Path(path).name if isinstance(path, str) else fallback


def _safe_detail(status: str, _detail: str) -> str:
    return {"ok": "Completed successfully", "cancelled": "Cancelled", "failed": "Operation failed"}[status]


def _repository_label(repository: object) -> str | None:
    return Path(repository).name if isinstance(repository, str) and repository else None


def _safe_summary(value: str | None) -> str | None:
    if not value:
        return None
    return value.replace("\n", " ")[:160]


def _delete_quarantined_tree(root: Path) -> None:
    """Remove only a quarantined tree, never crossing mounts or symlinks."""
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise OSError("quarantined image is not a real directory")
    device = root_info.st_dev
    for directory, directories, files, directory_fd in os.fwalk(root, topdown=False, follow_symlinks=False):
        info = os.lstat(directory, dir_fd=directory_fd)
        if info.st_dev != device:
            raise OSError("quarantined image crosses a filesystem boundary")
        for name in (*directories, *files):
            child = os.lstat(name, dir_fd=directory_fd)
            if child.st_dev != device:
                raise OSError("quarantined image crosses a filesystem boundary")
            if stat.S_ISDIR(child.st_mode) and not stat.S_ISLNK(child.st_mode):
                os.rmdir(name, dir_fd=directory_fd)
            else:
                os.unlink(name, dir_fd=directory_fd)
    os.rmdir(root)
