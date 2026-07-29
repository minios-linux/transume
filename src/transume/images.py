"""Read-only, conservative discovery of Clonezilla image directories."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
import re


class ImageType(StrEnum):
    SAVEDISK = "savedisk"
    SAVEPARTS = "saveparts"
    UNKNOWN = "unknown"


class ImageStatus(StrEnum):
    READY = "ready"
    CHECKING = "checking"
    NEEDS_VERIFICATION = "needs-verification"
    INCOMPLETE = "incomplete"
    DAMAGED = "damaged"
    ENCRYPTED = "encrypted"
    UNSUPPORTED = "unsupported"
    CHANGED = "changed"
    LOCATION_UNAVAILABLE = "location-unavailable"


class ImageProblemCode(StrEnum):
    NOT_DIRECTORY = "not-directory"
    SYMLINK_REJECTED = "symlink-rejected"
    MISSING_PARTS = "missing-parts"
    MISSING_DISK = "missing-disk"
    MISSING_PAYLOAD = "missing-payload"
    MISSING_SPLIT_SEGMENT = "missing-split-segment"
    UNREADABLE_METADATA = "unreadable-metadata"
    UNKNOWN_SOURCE_DISK = "unknown-source-disk"
    MALFORMED_TOPOLOGY = "malformed-topology"
    UNSUPPORTED_METADATA = "unsupported-metadata"
    ENCRYPTED_TOPOLOGY_UNAVAILABLE = "encrypted-topology-unavailable"


@dataclass(frozen=True, slots=True)
class ImageProblem:
    code: ImageProblemCode
    message: str
    path: str | None = None


@dataclass(frozen=True, slots=True)
class SourcePartition:
    name: str
    disk: str | None
    filesystem: str | None = None
    start: int | None = None
    size: int | None = None
    label: str | None = None
    partlabel: str | None = None
    included: bool | None = None


@dataclass(frozen=True, slots=True)
class SourceDisk:
    name: str
    size: int | None = None
    partition_table: str | None = None
    partitions: tuple[SourcePartition, ...] = ()
    model: str | None = None
    serial: str | None = None


@dataclass(frozen=True, slots=True)
class SourceTopology:
    disks: tuple[SourceDisk, ...] = ()
    partitions: tuple[SourcePartition, ...] = ()
    logical_size: int | None = None


@dataclass(frozen=True, slots=True)
class LvmPhysicalVolume:
    vg_name: str
    device_node: str
    uuid: str


@dataclass(frozen=True, slots=True)
class LvmLogicalVolume:
    device_node: str
    vg_name: str
    name: str
    file_metadata: str


@dataclass(frozen=True, slots=True)
class LvmVolumeGroup:
    name: str
    physical_volumes: tuple[LvmPhysicalVolume, ...]
    config_file: str


@dataclass(frozen=True, slots=True)
class LvmMetadata:
    volume_groups: tuple[LvmVolumeGroup, ...] = ()
    logical_volumes: tuple[LvmLogicalVolume, ...] = ()


@dataclass(frozen=True, slots=True)
class ImageCandidate:
    location_id: str
    path: Path
    relative_id: str
    name: str
    image_type: ImageType
    source_disks: tuple[str, ...]
    source_partitions: tuple[str, ...]
    topology: SourceTopology
    payload_files: tuple[str, ...]
    payload_size: int
    created_at: datetime | None
    modified_at: datetime | None
    compression: tuple[str, ...]
    split: bool
    encrypted: bool
    checksums: tuple[str, ...]
    status: ImageStatus
    problems: tuple[ImageProblem, ...]
    verified_at: datetime | None = None
    verification_current: bool = False
    logical_size: int | None = None
    clonezilla_version: str | None = None
    split_parts: int = 0
    metadata_warnings: tuple[ImageProblem, ...] = ()
    lvm: LvmMetadata = LvmMetadata()


_PAYLOAD = re.compile(
    r"^(?P<partition>.+?)(?:(?:\.[^.]+)?-ptcl-img|"
    r"\.(?:dd-img|ntfs-img|ntfsclone-img|partimage)|"
    r"(?:\.[^.]+)?-(?:dd-img|ntfs-img|ntfsclone-img|partimage))(?:[.-].*)?$"
)
_PARTITION_TABLE = re.compile(r"^(?P<disk>.+)-pt\.(?:parted|sf)$")
_COMPRESSION_SUFFIXES = {"gz": "gzip", "gzip": "gzip", "zst": "zstd", "zstd": "zstd", "lz4": "lz4", "xz": "xz", "lzma": "lzma", "bz2": "bzip2", "bzip2": "bzip2", "lzo": "lzo", "lz": "lzip", "lzip": "lzip", "lrz": "lrzip", "lrzip": "lrzip"}
_CHECKSUM = re.compile(r"(?:^|[-_.])(?:md5|sha1|sha256|sha512)(?:sum)?(?:[-_.]|$)|(?:^|[-_.])checksum(?:[-_.]|$)", re.I)
_ENCRYPTED = re.compile(r"(?:^|[-_.])(encrypt(?:ed)?|gpg|enc|aes)(?:[-_.]|$)", re.I)
# Legacy opaque-image markers remain recognized only to reject restoration
# without plaintext eCryptfs topology.
_OPAQUE_ENCRYPTION_MARKERS = {"go" + "cryptfs.conf", "go" + "cryptfs.diriv", "go" + "cryptfs.info"}
_ECRYPTFS_MARKERS = re.compile(r"(?:^|[._-])ecryptfs(?:[._-]|$)", re.I)
_DEVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ECRYPTFS_SIZE = re.compile(r"_([1-9][0-9]{0,12})MB\Z")
_ECRYPTFS_INFO_LIMIT = 16_384
_LVM_METADATA_LIMIT = 1_048_576
_LVM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}\Z")
_LVM_DEVICE = re.compile(r"/dev/[A-Za-z0-9._/+:-]+\Z")
_LVM_UUID = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+){6}\Z")


def parse_clonezilla_image(path: str | Path, *, location_id: str = "local") -> ImageCandidate:
    original = Path(path)
    if original.is_symlink():
        return _candidate(original.absolute(), location_id, ImageType.UNKNOWN, (), (), (), 0, (), False, False, (), [ImageProblem(ImageProblemCode.SYMLINK_REJECTED, "Image directory symlink was rejected", str(original))])
    try:
        root = original.resolve(strict=True)
    except OSError:
        root = original.absolute()
    problems: list[ImageProblem] = []
    warnings: list[ImageProblem] = []
    if not root.is_dir():
        return _candidate(root, location_id, ImageType.UNKNOWN, (), (), (), 0, (), False, False, (), [ImageProblem(ImageProblemCode.NOT_DIRECTORY, "Image path is not a directory", str(original))])
    files: dict[str, Path] = {}
    sizes: dict[str, int] = {}
    try:
        entries = list(root.iterdir())
    except OSError:
        entries = []
        problems.append(ImageProblem(ImageProblemCode.UNREADABLE_METADATA, "Image directory cannot be read", str(root)))
    for entry in entries:
        try:
            stat = entry.lstat()
        except OSError:
            continue
        if entry.is_symlink():
            problems.append(ImageProblem(ImageProblemCode.SYMLINK_REJECTED, "Symlinked image entry was rejected", entry.name))
        elif entry.is_file():
            files[entry.name], sizes[entry.name] = entry, stat.st_size

    encrypted = any(_ENCRYPTED.search(name) for name in files) or bool(_OPAQUE_ENCRYPTION_MARKERS & set(files)) or any(_ECRYPTFS_MARKERS.search(name) for name in files)
    ecryptfs = _ecryptfs_topology(files.get("ecryptfs.info")) if encrypted else None
    # Encrypted Clonezilla payload and marker names are opaque. Only its plaintext
    # ecryptfs.info is admissible topology evidence.
    parts = [] if encrypted else _names(files.get("parts"), problems)
    disks = [] if encrypted else _names(files.get("disk"), problems)
    table_disks = tuple(dict.fromkeys(match.group("disk") for name in files if (match := _PARTITION_TABLE.match(name))))
    payload_names = tuple(sorted(name for name in files if _PAYLOAD.match(name)))
    payload_parts = tuple(dict.fromkeys(match.group("partition") for name in payload_names if (match := _PAYLOAD.match(name))))
    lvm = _lvm_metadata(files, warnings) if not encrypted else LvmMetadata()
    lvm_physical_parts = {
        pv.device_node.removeprefix("/dev/")
        for group in lvm.volume_groups for pv in group.physical_volumes
    }
    image_type = ImageType.SAVEDISK if "disk" in files else (ImageType.SAVEPARTS if table_disks or parts else ImageType.UNKNOWN)
    if ecryptfs is not None:
        image_type, disks, partitions, topology = ecryptfs
        payload_names = ()
    if not encrypted and "parts" not in files:
        problems.append(ImageProblem(ImageProblemCode.MISSING_PARTS, "Required Clonezilla parts marker is missing", "parts"))
    if not encrypted and image_type is ImageType.SAVEDISK and not disks:
        problems.append(ImageProblem(ImageProblemCode.MISSING_DISK, "Savedisk image has no source disk metadata", "disk"))
    if not encrypted and "disk" not in files and not table_disks and image_type is not ImageType.UNKNOWN:
        warnings.append(ImageProblem(ImageProblemCode.UNKNOWN_SOURCE_DISK, "Source disks could not be inferred from optional partition metadata"))
    if not payload_names and ecryptfs is None:
        problems.append(ImageProblem(ImageProblemCode.MISSING_PAYLOAD, "No recognized Clonezilla payload files were found"))
    elif not encrypted:
        for partition in parts:
            if partition not in payload_parts and partition not in lvm_physical_parts:
                problems.append(ImageProblem(
                    ImageProblemCode.MISSING_PAYLOAD,
                    "Clonezilla partition payload is missing",
                    partition,
                ))
        for logical in lvm.logical_volumes:
            payload_name = logical.device_node.removeprefix("/dev/").replace("/", "-")
            if payload_name not in payload_parts:
                problems.append(ImageProblem(
                    ImageProblemCode.MISSING_PAYLOAD,
                    "Clonezilla LVM logical volume payload is missing",
                    logical.device_node,
                ))
    if not disks and ecryptfs is None:
        disks = list(table_disks)
    partitions = tuple(dict.fromkeys(parts or payload_parts)) if ecryptfs is None else partitions
    if not encrypted:
        fs, labels, partlabels = _filesystem_map(files.get("blkid.list"), files.get("dev-fs.list"), problems=warnings)
        disk_meta = _disk_metadata(files.get("blkdev.list"), warnings)
        layouts = _layouts(files, warnings)
        topology = _topology(tuple(disks), partitions, table_disks, fs, labels, partlabels, disk_meta, layouts, warnings)
    elif ecryptfs is None:
        topology = SourceTopology()
    compression = _compression(payload_names)
    split_parts, split_missing = _split_parts(payload_names)
    if split_missing:
        problems.extend(ImageProblem(ImageProblemCode.MISSING_SPLIT_SEGMENT, "Payload split segment is missing", name) for name in split_missing)
    if encrypted and ecryptfs is None:
        problems.append(ImageProblem(ImageProblemCode.ENCRYPTED_TOPOLOGY_UNAVAILABLE, "Encrypted image topology is unavailable until decryption"))
    version = None if encrypted else _clonezilla_version(files, warnings)
    return _candidate(root, location_id, image_type, tuple(disks), partitions, payload_names, sum(sizes[name] for name in payload_names), compression, bool(split_parts), encrypted, tuple(sorted(name for name in files if _CHECKSUM.search(name))), problems, topology, version, split_parts, warnings, lvm)


def _ecryptfs_topology(path: Path | None) -> tuple[ImageType, tuple[str, ...], tuple[str, ...], SourceTopology] | None:
    if path is None:
        return None
    try:
        with path.open("rb") as handle:
            data = handle.read(_ECRYPTFS_INFO_LIMIT + 1)
        if len(data) > _ECRYPTFS_INFO_LIMIT:
            return None
        text = data.decode("ascii")
    except (OSError, UnicodeError):
        return None
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*)=\"([^\"\r\n]{0,4096})\"", line)
        if match:
            if match.group(1) in values:
                return None
            values[match.group(1)] = match.group(2)
        elif "=" in line:
            return None
    disks = tuple(values.get("disk_of_img", "").split())
    parts = tuple(values.get("parts_of_img", "").split())
    size = _ECRYPTFS_SIZE.fullmatch(values.get("disks_size_all_of_img", ""))
    if (not disks or not parts or size is None or any(not _DEVICE_NAME.fullmatch(value) for value in (*disks, *parts))):
        return None
    # A disk list denotes savedisk; Clonezilla saveparts records only its parts.
    image_type = ImageType.SAVEDISK
    bytes_total = int(size.group(1)) * 1_000_000
    partitions = tuple(SourcePartition(name, next((disk for disk in disks if _belongs_to_disk(name, disk)), None), included=True) for name in parts)
    source_disks = tuple(SourceDisk(name, bytes_total if len(disks) == 1 else None,
                                    partitions=tuple(part for part in partitions if part.disk == name)) for name in disks)
    return image_type, disks, parts, SourceTopology(source_disks, partitions, bytes_total)


def parse_image_directory(path: str | Path, *, location_id: str = "local") -> ImageCandidate:
    return parse_clonezilla_image(path, location_id=location_id)


def _lines(path: Path | None, problems: list[ImageProblem]) -> list[str]:
    if path is None:
        return []
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeError):
        problems.append(ImageProblem(ImageProblemCode.UNREADABLE_METADATA, "Metadata file cannot be decoded", path.name))
        return []


def _names(path: Path | None, problems: list[ImageProblem]) -> list[str]:
    """Read Clonezilla device lists, which may be line- or space-delimited."""
    return [name for line in _lines(path, problems) for name in line.split()]


def _filesystem_map(*paths: Path | None, problems: list[ImageProblem]) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    fs: dict[str, str] = {}; labels: dict[str, str] = {}; partlabels: dict[str, str] = {}
    for path in paths:
        for line in _lines(path, problems):
            name = re.search(r"(?:/dev/)?(?P<name>[^:\s]+)", line)
            if not name:
                continue
            for key, target in (("TYPE", fs), ("LABEL", labels), ("PARTLABEL", partlabels)):
                match = re.search(rf"{key}=(?:[\"'](?P<quoted>.*?)[\"']|(?P<plain>[^\s]+))", line)
                if match:
                    target[name.group("name")] = match.group("quoted") or match.group("plain")
    return fs, labels, partlabels


def _lvm_metadata(files: dict[str, Path], warnings: list[ImageProblem]) -> LvmMetadata:
    pv_path, lv_path = files.get("lvm_vg_dev.list"), files.get("lvm_logv.list")
    if pv_path is None and lv_path is None:
        return LvmMetadata()
    try:
        if pv_path is None or lv_path is None:
            raise ValueError("incomplete LVM metadata")
        pv_lines = _bounded_metadata_lines(pv_path)
        lv_lines = _bounded_metadata_lines(lv_path)
        physical: list[LvmPhysicalVolume] = []
        seen_devices: set[str] = set()
        seen_uuids: set[str] = set()
        for line in pv_lines:
            fields = line.split()
            if (len(fields) != 3 or not _LVM_NAME.fullmatch(fields[0])
                    or not _LVM_DEVICE.fullmatch(fields[1])
                    or not _LVM_UUID.fullmatch(fields[2])
                    or fields[1] in seen_devices or fields[2] in seen_uuids):
                raise ValueError("invalid LVM physical volume metadata")
            physical.append(LvmPhysicalVolume(*fields))
            seen_devices.add(fields[1]); seen_uuids.add(fields[2])
        if not physical:
            raise ValueError("empty LVM physical volume metadata")
        groups: list[LvmVolumeGroup] = []
        group_names = tuple(dict.fromkeys(item.vg_name for item in physical))
        for name in group_names:
            config_name = f"lvm_{name}.conf"
            config = files.get(config_name)
            if config is None or config.stat().st_size > _LVM_METADATA_LIMIT:
                raise ValueError("LVM volume group configuration is unavailable")
            groups.append(LvmVolumeGroup(
                name, tuple(item for item in physical if item.vg_name == name), config_name,
            ))
        logical: list[LvmLogicalVolume] = []
        seen_logical: set[str] = set()
        for line in lv_lines:
            if "  " not in line:
                raise ValueError("invalid LVM logical volume metadata")
            device, metadata = line.split("  ", 1)
            parts = device.split("/")
            if (len(parts) != 4 or parts[:2] != ["", "dev"]
                    or parts[2] not in group_names or not _LVM_NAME.fullmatch(parts[3])
                    or not metadata.strip() or device in seen_logical):
                raise ValueError("invalid LVM logical volume metadata")
            logical.append(LvmLogicalVolume(device, parts[2], parts[3], metadata.strip()))
            seen_logical.add(device)
        if not logical:
            raise ValueError("empty LVM logical volume metadata")
        return LvmMetadata(tuple(groups), tuple(logical))
    except (OSError, UnicodeError, ValueError):
        warnings.append(ImageProblem(
            ImageProblemCode.UNSUPPORTED_METADATA,
            "LVM metadata is incomplete or malformed",
            "lvm_vg_dev.list" if pv_path is not None else "lvm_logv.list",
        ))
        return LvmMetadata()


def _bounded_metadata_lines(path: Path) -> list[str]:
    if path.stat().st_size > _LVM_METADATA_LIMIT:
        raise ValueError("metadata is too large")
    values = path.read_text(encoding="utf-8").splitlines()
    if not values or any(not line.strip() for line in values):
        raise ValueError("metadata contains empty records")
    return [line.strip() for line in values]


def _disk_metadata(path: Path | None, problems: list[ImageProblem]) -> dict[str, tuple[int | None, str | None, str | None]]:
    result: dict[str, tuple[int | None, str | None, str | None]] = {}
    for line in _lines(path, problems):
        quoted = dict(re.findall(r"(NAME|SIZE|MODEL|SERIAL)=\"([^\"]*)\"", line))
        if quoted.get("NAME"):
            result[quoted["NAME"].removeprefix("/dev/")] = (_number(quoted.get("SIZE")), quoted.get("MODEL") or None, quoted.get("SERIAL") or None)
            continue
        fields = line.split()
        if fields and re.fullmatch(r"(?:/dev/)?[\w.-]+", fields[0]) and len(fields) > 1 and fields[1].isdigit():
            result[fields[0].removeprefix("/dev/")] = (int(fields[1]), None, None)
    return result


def _layouts(files: dict[str, Path], warnings: list[ImageProblem]) -> dict[str, tuple[str | None, dict[str, tuple[int | None, int | None, str | None]], int | None]]:
    result: dict[str, tuple[str | None, dict[str, tuple[int | None, int | None, str | None]], int | None]] = {}
    for name, path in files.items():
        match = _PARTITION_TABLE.match(name)
        if not match:
            continue
        disk, rows, table, disk_size = match.group("disk"), {}, None, None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            warnings.append(ImageProblem(ImageProblemCode.UNREADABLE_METADATA, "Partition metadata cannot be decoded", name)); continue
        for line in text.splitlines():
            machine = re.match(r"\s*(\d+):([0-9]+)s:([0-9]+)s:([0-9]+)s:([^:]*):([^:]*):?", line)
            sf = re.match(r"\s*/dev/(\S+)\s*:\s*start=\s*(\d+),\s*size=\s*(\d+)", line)
            human = re.match(r"\s*(\d+)\s+(\d+)s\s+(\d+)s\s+(\d+)s(?:\s+(\S+))?", line)
            if machine:
                number, start, end, _size, filesystem, label = machine.groups()
                rows[_partition_name(disk, number)] = (int(start) * 512, (int(end) - int(start) + 1) * 512, filesystem or None)
            elif sf:
                partition, start, size = sf.groups()
                rows[partition] = (int(start) * 512, int(size) * 512, None)
            elif human:
                number, start, end, _size, filesystem = human.groups()
                rows[_partition_name(disk, number)] = (int(start) * 512, (int(end) - int(start) + 1) * 512, filesystem or None)
            table_match = re.search(r"(?:^|\s)label:\s*(gpt|dos)\b", line, re.I)
            if table_match:
                table = "gpt" if table_match.group(1).lower() == "gpt" else "mbr"
            human_table = re.match(r"\s*Partition Table:\s*(gpt|msdos)\b", line, re.I)
            if human_table:
                table = "gpt" if human_table.group(1).lower() == "gpt" else "mbr"
            machine_table = re.match(r"\s*/dev/[^:]+:(?:[^:]*:){4}(gpt|msdos):", line, re.I)
            if machine_table:
                table = "gpt" if machine_table.group(1).lower() == "gpt" else "mbr"
            human_size = re.match(r"\s*Disk\s+/dev/\S+:\s*(\d+)s\s*$", line)
            if human_size:
                disk_size = int(human_size.group(1)) * 512
        if not rows and table is None and disk_size is None and text.strip():
            warnings.append(ImageProblem(ImageProblemCode.MALFORMED_TOPOLOGY, "Partition metadata format is unsupported or malformed", name))
        old_table, old_rows, old_size = result.get(disk, (None, {}, None))
        result[disk] = (table or old_table, {**old_rows, **rows}, disk_size or old_size)
    for name in files:
        marker = re.match(r"(.+)-(gpt|mbr)(?:[.-]|$)", name, re.I)
        if marker:
            disk, table = marker.groups()
            old = result.get(disk, (None, {}, None))
            result[disk] = (table.lower(), old[1], old[2])
    return result


def _topology(disks: tuple[str, ...], partitions: tuple[str, ...], table_disks: tuple[str, ...], fs: dict[str, str], labels: dict[str, str], partlabels: dict[str, str], disk_meta: dict[str, tuple[int | None, str | None, str | None]], layouts: dict[str, tuple[str | None, dict[str, tuple[int | None, int | None, str | None]], int | None]], warnings: list[ImageProblem]) -> SourceTopology:
    result: list[SourceDisk] = []; mapped: list[SourcePartition] = []
    for disk in disks:
        layout_table, rows, layout_size = layouts.get(disk, ("parted" if disk in table_disks else None, {}, None))
        owned = []
        for name in partitions:
            if _belongs_to_disk(name, disk):
                start, size, layout_fs = rows.get(name, (None, None, None))
                owned.append(SourcePartition(name, disk, fs.get(name, layout_fs), start, size, labels.get(name), partlabels.get(name), True))
        size, model, serial = disk_meta.get(disk, (None, None, None))
        size = size or layout_size
        result.append(SourceDisk(disk, size, layout_table, tuple(owned), model, serial)); mapped.extend(owned)
    for name in partitions:
        if not any(part.name == name for part in mapped):
            warnings.append(ImageProblem(ImageProblemCode.UNKNOWN_SOURCE_DISK, "Partition could not be assigned to a source disk", name))
            mapped.append(SourcePartition(name, None, fs.get(name), label=labels.get(name), partlabel=partlabels.get(name), included=True))
    logical = sum(disk.size for disk in result if disk.size is not None) if result and all(disk.size is not None for disk in result) else None
    return SourceTopology(tuple(result), tuple(mapped), logical)


def _split_parts(names: tuple[str, ...]) -> tuple[int, tuple[str, ...]]:
    groups: dict[str, list[str]] = {}
    for name in names:
        match = re.match(r"(.+)\.(\d{3,}|[a-z]{2})$", name, re.I)
        if match:
            groups.setdefault(match.group(1), []).append(match.group(2).lower())
    missing: list[str] = []
    for base, values in groups.items():
        if all(value.isdigit() for value in values):
            width = len(values[0]); expected = [f"{number:0{width}d}" for number in range(int(min(values)), int(max(values)) + 1)]
        elif all(re.fullmatch(r"[a-z]{2}", value) for value in values):
            expected = [_alpha_chunk(number) for number in range(_alpha_value(min(values)), _alpha_value(max(values)) + 1)]
        else:
            continue
        missing.extend(f"{base}.{value}" for value in expected if value not in values)
    return sum(len(values) for values in groups.values()), tuple(missing)


def _compression(names: tuple[str, ...]) -> tuple[str, ...]:
    values = {
        value
        for name in names
        for suffix, value in _COMPRESSION_SUFFIXES.items()
        if re.search(rf"\.{re.escape(suffix)}(?:\.|$)", name, re.I)
    }
    return tuple(sorted(values))


def _clonezilla_version(files: dict[str, Path], problems: list[ImageProblem]) -> str | None:
    for name in ("Info-img-id.txt", "Info-packages.txt", "Info-saved-by-cmd.txt", "Info-OS-prober.txt"):
        for line in _lines(files.get(name), problems):
            match = re.search(r"(?:clonezilla(?:[-_ ](?:live|utils))?|ocs[-_]?(?:live|sr))[^0-9]*([0-9][\w.+:-]*)", line, re.I)
            if match:
                return match.group(1)
    return None


def _belongs_to_disk(partition: str, disk: str) -> bool:
    return partition.startswith(disk + "p") or bool(re.fullmatch(re.escape(disk) + r"\d+", partition))


def _partition_name(disk: str, number: str) -> str:
    return f"{disk}p{number}" if re.search(r"(?:\d|mmcblk|nvme)", disk) else f"{disk}{number}"


def _number(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def _alpha_value(value: str) -> int:
    return (ord(value[0]) - 97) * 26 + ord(value[1]) - 97


def _alpha_chunk(value: int) -> str:
    return chr(value // 26 + 97) + chr(value % 26 + 97)


def _candidate(root: Path, location_id: str, image_type: ImageType, disks: tuple[str, ...], partitions: tuple[str, ...], payloads: tuple[str, ...], payload_size: int, compression: tuple[str, ...], split: bool, encrypted: bool, checksums: tuple[str, ...], problems: list[ImageProblem], topology: SourceTopology | None = None, version: str | None = None, split_parts: int = 0, warnings: list[ImageProblem] | None = None, lvm: LvmMetadata | None = None) -> ImageCandidate:
    try: timestamp = datetime.fromtimestamp(root.stat().st_mtime, timezone.utc)
    except OSError: timestamp = None
    codes = {problem.code for problem in problems}
    if codes & {ImageProblemCode.NOT_DIRECTORY, ImageProblemCode.SYMLINK_REJECTED}: status = ImageStatus.UNSUPPORTED
    elif encrypted: status = ImageStatus.ENCRYPTED
    elif ImageProblemCode.MISSING_SPLIT_SEGMENT in codes: status = ImageStatus.DAMAGED
    elif codes & {ImageProblemCode.MISSING_PARTS, ImageProblemCode.MISSING_DISK, ImageProblemCode.MISSING_PAYLOAD, ImageProblemCode.UNREADABLE_METADATA}: status = ImageStatus.INCOMPLETE
    elif checksums: status = ImageStatus.NEEDS_VERIFICATION
    else: status = ImageStatus.READY
    topology = topology or SourceTopology()
    return ImageCandidate(location_id, root, root.name, root.name, image_type, disks, partitions, topology, payloads, payload_size, timestamp, timestamp, compression, split, encrypted, checksums, status, tuple(problems), logical_size=topology.logical_size, clonezilla_version=version, split_parts=split_parts, metadata_warnings=tuple(warnings or ()), lvm=lvm or LvmMetadata())
