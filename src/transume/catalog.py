"""Persistent, credential-free catalog of discovered Clonezilla images."""

from __future__ import annotations

from concurrent.futures import Executor, Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import json
import os
from pathlib import Path
import tempfile
from threading import Event
from typing import Callable, Iterable

from .images import (
    ImageCandidate,
    ImageProblem,
    ImageProblemCode,
    ImageStatus,
    ImageType,
    LvmLogicalVolume,
    LvmMetadata,
    LvmPhysicalVolume,
    LvmVolumeGroup,
    SourceDisk,
    SourcePartition,
    SourceTopology,
    parse_clonezilla_image,
)
from .storage import StorageKind, StorageLocation


SCHEMA_VERSION = 4


class Availability(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class CatalogLocation:
    id: str
    location: StorageLocation

    def __post_init__(self) -> None:
        if not self.id or "/" in self.id or "\\" in self.id:
            raise ValueError("location id must be a non-empty identifier")


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    candidate: ImageCandidate
    scope: str
    availability: Availability = Availability.AVAILABLE
    last_seen_at: datetime | None = None
    verified_at: datetime | None = None
    verification_fingerprint: tuple[tuple[str, int, int], ...] | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    location_id: str
    scope: str
    candidates: tuple[ImageCandidate, ...]
    problems: tuple[ImageProblem, ...]
    partial: bool
    started_at: datetime
    finished_at: datetime


class ImageCatalog:
    """Catalog whose on-disk representation contains no mount credentials."""

    def __init__(self, path: str | Path, locations: Iterable[CatalogLocation] = (), *, executor: Executor | None = None) -> None:
        self.path = Path(path)
        self.locations: dict[str, StorageLocation] = {}
        self.entries: list[CatalogEntry] = []
        self._executor = executor
        self._owned_executor: ThreadPoolExecutor | None = None
        self.load()
        for item in locations:
            self.add_location(item.id, item.location, persist=False)

    def add_location(self, location_id: str, location: StorageLocation, *, persist: bool = True) -> None:
        CatalogLocation(location_id, location)
        self.locations[location_id] = location
        if persist:
            self.save()

    def scan(
        self,
        location_id: str,
        root: str | Path | None = None,
        *,
        recursive_depth: int = 0,
        cancel_event: Event | None = None,
    ) -> ScanResult:
        if recursive_depth < 0:
            raise ValueError("recursive_depth must not be negative")
        location = self.locations[location_id]
        requested = Path(root) if root is not None else Path(location.root)
        started = _now()
        problems: list[ImageProblem] = []
        partial = False
        if requested.is_symlink():
            problems.append(_problem(ImageProblemCode.SYMLINK_REJECTED, "Scan root symlink was rejected", requested))
            return ScanResult(location_id, str(requested.absolute()), (), tuple(problems), False, started, _now())
        try:
            scope_path = requested.resolve(strict=True)
        except OSError:
            problems.append(_problem(ImageProblemCode.NOT_DIRECTORY, "Scan root is not an accessible directory", requested))
            return ScanResult(location_id, str(requested.absolute()), (), tuple(problems), False, started, _now())
        if not scope_path.is_dir():
            problems.append(_problem(ImageProblemCode.NOT_DIRECTORY, "Scan root is not a directory", scope_path))
            return ScanResult(location_id, str(scope_path), (), tuple(problems), False, started, _now())

        candidates: list[ImageCandidate] = []
        # A selected image directory is a candidate itself, not merely its parent.
        if _looks_like_image(scope_path):
            candidates.append(_with_relative_id(parse_clonezilla_image(scope_path, location_id=location_id), scope_path, scope_path))

        pending: list[tuple[Path, int]] = [(scope_path, 0)]
        while pending:
            if _cancelled(cancel_event):
                partial = True
                break
            directory, depth = pending.pop()
            try:
                children = list(directory.iterdir())
            except OSError:
                problems.append(_problem(ImageProblemCode.UNREADABLE_METADATA, "Directory cannot be read", directory))
                continue
            for child in children:
                if _cancelled(cancel_event):
                    partial = True
                    break
                try:
                    child.lstat()
                except OSError:
                    problems.append(_problem(ImageProblemCode.UNREADABLE_METADATA, "Directory entry cannot be read", child))
                    continue
                if child.is_symlink():
                    problems.append(_problem(ImageProblemCode.SYMLINK_REJECTED, "Symlinked scan entry was rejected", child))
                    continue
                if not child.is_dir():
                    continue
                try:
                    canonical = child.resolve(strict=True)
                    canonical.relative_to(scope_path)
                except (OSError, ValueError):
                    problems.append(_problem(ImageProblemCode.SYMLINK_REJECTED, "Directory escapes scan root and was rejected", child))
                    continue
                if _looks_like_image(canonical):
                    candidates.append(_with_relative_id(parse_clonezilla_image(canonical, location_id=location_id), canonical, scope_path))
                if depth < recursive_depth:
                    pending.append((canonical, depth + 1))
            if partial:
                break
        return ScanResult(location_id, str(scope_path), tuple(candidates), tuple(problems), partial, started, _now())

    def scan_async(self, *args: object, callback: Callable[[ScanResult], None] | None = None, **kwargs: object) -> Future[ScanResult]:
        executor = self._executor
        if executor is None:
            self._owned_executor = self._owned_executor or ThreadPoolExecutor(max_workers=1)
            executor = self._owned_executor
        future = executor.submit(self.scan, *args, **kwargs)
        if callback:
            future.add_done_callback(lambda completed: callback(completed.result()))
        return future

    def refresh(self, location_id: str, root: str | Path | None = None, **kwargs: object) -> ScanResult:
        result = self.scan(location_id, root, **kwargs)
        if result.partial:
            return result
        current = {candidate.relative_id: candidate for candidate in result.candidates}
        replaced: list[CatalogEntry] = []
        for entry in self.entries:
            if entry.candidate.location_id == location_id and entry.scope == result.scope:
                candidate = current.pop(entry.candidate.relative_id, None)
                if candidate is None:
                    # A retained entry is not actionable while its scanned location is absent.
                    replaced.append(CatalogEntry(replace(entry.candidate, status=ImageStatus.LOCATION_UNAVAILABLE), entry.scope, Availability.UNAVAILABLE, entry.last_seen_at, entry.verified_at, entry.verification_fingerprint))
                else:
                    fingerprint = _fingerprint(candidate)
                    verified = entry.verified_at if entry.verification_fingerprint == fingerprint else None
                    replaced.append(CatalogEntry(_with_verification(candidate, verified, fingerprint), result.scope, Availability.AVAILABLE, result.finished_at, verified, fingerprint if verified else None))
            else:
                replaced.append(entry)
        replaced.extend(CatalogEntry(candidate, result.scope, Availability.AVAILABLE, result.finished_at) for candidate in current.values())
        self.entries = replaced
        self.save()
        visible = tuple(
            next((entry.candidate for entry in self.entries
                  if entry.candidate.location_id == candidate.location_id
                  and entry.candidate.relative_id == candidate.relative_id
                  and entry.scope == result.scope
                  and entry.availability is Availability.AVAILABLE), candidate)
            for candidate in result.candidates
        )
        return ScanResult(result.location_id, result.scope, visible, result.problems,
                          result.partial, result.started_at, result.finished_at)

    def mark_location_unavailable(self, location_id: str) -> None:
        """Retain history while preventing actions after an ephemeral mount ends."""
        changed = False
        updated: list[CatalogEntry] = []
        for entry in self.entries:
            if entry.candidate.location_id == location_id:
                updated.append(CatalogEntry(replace(entry.candidate, status=ImageStatus.LOCATION_UNAVAILABLE),
                                            entry.scope, Availability.UNAVAILABLE, entry.last_seen_at,
                                            entry.verified_at, entry.verification_fingerprint))
                changed = True
            else:
                updated.append(entry)
        if changed:
            self.entries = updated
            self.save()

    def mark_verified(self, candidate: ImageCandidate) -> ImageCandidate:
        """Record a successful check only for the exact payload that was checked."""
        fingerprint = _fingerprint(candidate)
        verified_at = _now()
        updated: list[CatalogEntry] = []
        marked: ImageCandidate | None = None
        for entry in self.entries:
            if (entry.candidate.location_id == candidate.location_id
                    and entry.candidate.relative_id == candidate.relative_id
                    and entry.availability is Availability.AVAILABLE):
                value = _with_verification(entry.candidate, verified_at, fingerprint)
                updated.append(CatalogEntry(value, entry.scope, entry.availability, entry.last_seen_at, verified_at, fingerprint))
                marked = value
            else:
                updated.append(entry)
        if marked is None:
            raise ValueError("image is not in the current catalog")
        self.entries = updated
        self.save()
        return marked

    def clear_verification(self, candidate: ImageCandidate) -> None:
        """Invalidate retained evidence after a name or payload mutation."""
        self.entries = [
            CatalogEntry(replace(entry.candidate, verified_at=None, verification_current=False),
                         entry.scope, entry.availability, entry.last_seen_at, None, None)
            if entry.candidate.location_id == candidate.location_id and entry.candidate.relative_id == candidate.relative_id
            else entry
            for entry in self.entries
        ]
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"schema_version": SCHEMA_VERSION, "locations": [_location_data(key, value) for key, value in sorted(self.locations.items())], "entries": [_entry_data(entry) for entry in self.entries]}
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = -1
                json.dump(data, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except BaseException:
            if fd != -1:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open(encoding="utf-8") as stream:
                data = json.load(stream)
            if data.get("schema_version") not in {1, 2, 3, SCHEMA_VERSION}:
                raise ValueError("unsupported image catalog schema")
            self.locations = {item["id"]: _location_from_data(item) for item in data.get("locations", [])}
            self.entries = [_entry_from_data(item) for item in data.get("entries", [])]
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            quarantine = self.path.with_name(
                f"{self.path.name}.corrupt-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
            )
            try:
                os.replace(self.path, quarantine)
            except OSError:
                pass
            self.locations = {}
            self.entries = []


def _looks_like_image(path: Path) -> bool:
    try:
        return any(
            entry.name in {"parts", "disk", "ecryptfs.info", "gocryptfs.conf", "gocryptfs.diriv", "gocryptfs.info"}
            or "-pt." in entry.name or "-ptcl-img" in entry.name
            or ".partimage" in entry.name or "-dd-img" in entry.name
            for entry in path.iterdir()
        )
    except OSError:
        return False


def _cancelled(event: Event | None) -> bool:
    return event is not None and event.is_set()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _problem(code: ImageProblemCode, message: str, path: Path) -> ImageProblem:
    return ImageProblem(code, message, str(path))


def _time_data(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _time_from_data(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _location_data(location_id: str, location: StorageLocation) -> dict[str, object]:
    return {"id": location_id, "kind": location.kind.value, "root": location.root, "host": location.host, "endpoint": location.endpoint, "share": location.share, "device": location.device, "username": location.username, "port": location.port}


def _location_from_data(data: dict[str, object]) -> StorageLocation:
    return StorageLocation(StorageKind(data["kind"]), data["root"], host=data.get("host"), endpoint=data.get("endpoint"), share=data.get("share"), device=data.get("device"), username=data.get("username"), port=data.get("port"))  # type: ignore[arg-type]


def _entry_data(entry: CatalogEntry) -> dict[str, object]:
    candidate = entry.candidate
    return {"scope": entry.scope, "availability": entry.availability.value, "last_seen_at": _time_data(entry.last_seen_at), "verified_at": _time_data(entry.verified_at), "verification_fingerprint": entry.verification_fingerprint, "candidate": {"location_id": candidate.location_id, "path": str(candidate.path), "relative_id": candidate.relative_id, "name": candidate.name, "image_type": candidate.image_type.value, "source_disks": candidate.source_disks, "source_partitions": candidate.source_partitions, "payload_files": candidate.payload_files, "payload_size": candidate.payload_size, "logical_size": candidate.logical_size, "clonezilla_version": candidate.clonezilla_version, "split_parts": candidate.split_parts, "created_at": _time_data(candidate.created_at), "modified_at": _time_data(candidate.modified_at), "compression": candidate.compression, "split": candidate.split, "encrypted": candidate.encrypted, "checksums": candidate.checksums, "status": candidate.status.value, "problems": [{"code": item.code.value, "message": item.message, "path": item.path} for item in candidate.problems], "metadata_warnings": [{"code": item.code.value, "message": item.message, "path": item.path} for item in candidate.metadata_warnings], "lvm": {"volume_groups": [{"name": group.name, "config_file": group.config_file, "physical_volumes": [{"vg_name": pv.vg_name, "device_node": pv.device_node, "uuid": pv.uuid} for pv in group.physical_volumes]} for group in candidate.lvm.volume_groups], "logical_volumes": [{"device_node": lv.device_node, "vg_name": lv.vg_name, "name": lv.name, "file_metadata": lv.file_metadata} for lv in candidate.lvm.logical_volumes]}, "topology": {"logical_size": candidate.topology.logical_size, "disks": [{"name": disk.name, "size": disk.size, "partition_table": disk.partition_table, "model": disk.model, "serial": disk.serial, "partitions": [_part_data(part) for part in disk.partitions]} for disk in candidate.topology.disks], "partitions": [_part_data(part) for part in candidate.topology.partitions]}}}


def _part_data(part: SourcePartition) -> dict[str, object]:
    return {"name": part.name, "disk": part.disk, "filesystem": part.filesystem, "start": part.start, "size": part.size, "label": part.label, "partlabel": part.partlabel, "included": part.included}


def _entry_from_data(data: dict[str, object]) -> CatalogEntry:
    raw = data["candidate"]  # type: ignore[index]
    topology = raw.get("topology", {})  # type: ignore[union-attr]
    def part(item: dict[str, object]) -> SourcePartition:
        return SourcePartition(item["name"], item.get("disk"), item.get("filesystem"), item.get("start"), item.get("size"), item.get("label"), item.get("partlabel"), item.get("included"))  # type: ignore[arg-type]
    disks = tuple(SourceDisk(item["name"], item.get("size"), item.get("partition_table"), tuple(part(value) for value in item.get("partitions", [])), item.get("model"), item.get("serial")) for item in topology.get("disks", []))  # type: ignore[union-attr,arg-type]
    fingerprint = data.get("verification_fingerprint")
    verified_at = _time_from_data(data.get("verified_at"))
    normalized = tuple((str(value[0]), int(value[1]), int(value[2])) for value in fingerprint) if fingerprint else None  # type: ignore[index]
    lvm = raw.get("lvm", {})
    groups = tuple(LvmVolumeGroup(
        value["name"],
        tuple(LvmPhysicalVolume(item["vg_name"], item["device_node"], item["uuid"])
              for item in value.get("physical_volumes", [])),
        value["config_file"],
    ) for value in lvm.get("volume_groups", []))
    logical = tuple(LvmLogicalVolume(value["device_node"], value["vg_name"], value["name"], value["file_metadata"])
                    for value in lvm.get("logical_volumes", []))
    candidate = ImageCandidate(raw["location_id"], Path(raw["path"]), raw["relative_id"], raw["name"], ImageType(raw["image_type"]), tuple(raw["source_disks"]), tuple(raw["source_partitions"]), SourceTopology(disks, tuple(part(value) for value in topology.get("partitions", [])), topology.get("logical_size")), tuple(raw["payload_files"]), raw["payload_size"], _time_from_data(raw.get("created_at")), _time_from_data(raw.get("modified_at")), tuple(raw["compression"]), raw["split"], raw["encrypted"], tuple(raw["checksums"]), ImageStatus(raw["status"]), tuple(ImageProblem(ImageProblemCode(value["code"]), value["message"], value.get("path")) for value in raw["problems"]), verified_at, verified_at is not None, raw.get("logical_size"), raw.get("clonezilla_version"), raw.get("split_parts", 0), tuple(ImageProblem(ImageProblemCode(value["code"]), value["message"], value.get("path")) for value in raw.get("metadata_warnings", [])), LvmMetadata(groups, logical))  # type: ignore[index,arg-type,union-attr]
    return CatalogEntry(candidate, data["scope"], Availability(data.get("availability", "available")), _time_from_data(data.get("last_seen_at")), verified_at, normalized)  # type: ignore[arg-type]


def _with_relative_id(candidate: ImageCandidate, path: Path, scope: Path) -> ImageCandidate:
    try:
        relative_id = path.relative_to(scope).as_posix()
    except ValueError:
        relative_id = path.name
    return replace(candidate, relative_id=relative_id)


def _fingerprint(candidate: ImageCandidate) -> tuple[tuple[str, int, int], ...]:
    values = []
    for name in candidate.payload_files:
        try:
            stat = (candidate.path / name).lstat()
        except OSError:
            return ()
        values.append((name, stat.st_size, stat.st_mtime_ns))
    return tuple(values)


def _with_verification(candidate: ImageCandidate, verified_at: datetime | None,
                       fingerprint: tuple[tuple[str, int, int], ...]) -> ImageCandidate:
    return replace(candidate, verified_at=verified_at, verification_current=verified_at is not None and _fingerprint(candidate) == fingerprint)
