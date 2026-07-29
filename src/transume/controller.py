"""Translate UI drafts into immutable, validated job specifications."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import re
from uuid import uuid4

from .domain import JobOperation, PublicJobSpec
from .draft import BackupOptions, CloneOptions, JobDraft, RestoreOptions, image_fingerprint
from .images import ImageCandidate, ImageStatus, ImageType, parse_clonezilla_image


_IMAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DEFAULT_OPTIONS = {
    "backup": {"compression": "zstd", "engine": "partclone", "verify_image": True, "rescue": False,
               "filesystem_check": "check", "checksum": "none", "image_size": 0, "encrypt": False, "post_action": "none"},
    "restore": {"check_image": True, "resize": False, "restore_mbr": True, "partition_table": "original",
                  "restore_ebr": True, "hidden_data": False, "update_efi": True, "encrypted": False,
                  "source_partition": "", "post_action": "none"},
    "clone": {"resize": False, "rescue": False, "force_dd": False, "hidden_data": False,
              "direct_io": False, "post_action": "none"},
}
_OPTION_VALUES = {
    "backup": {"compression": {"zstd", "lz4", "gzip", "xz", "lzma", "bzip2", "lzo", "lzip", "lrzip", "none"}, "engine": {"partclone", "dd", "ntfsclone"}, "verify_image": bool, "rescue": bool, "filesystem_check": {"skip", "check", "repair"}, "checksum": {"none", "md5", "sha1", "files"}, "image_size": int, "encrypt": bool, "post_action": {"none", "poweroff", "reboot"}},
    "restore": {"check_image": bool, "resize": bool, "restore_mbr": bool, "partition_table": {"original", "proportional", "existing"}, "restore_ebr": bool, "hidden_data": bool, "update_efi": bool, "encrypted": bool, "source_partition": str, "post_action": {"none", "poweroff", "reboot"}},
    "clone": {"resize": bool, "rescue": bool, "force_dd": bool, "hidden_data": bool, "direct_io": bool, "post_action": {"none", "poweroff", "reboot"}},
}


def _options(operation: str, selection: dict[str, Any]) -> dict[str, str | bool | int]:
    selected = selection.get("options", {})
    if not isinstance(selected, dict):
        raise ValueError("options must be a mapping")
    values = dict(_DEFAULT_OPTIONS[operation])
    values.update(selected)
    allowed = _OPTION_VALUES[operation]
    if set(values) - set(allowed):
        raise ValueError("unsupported option")
    for key, value in values.items():
        expected = allowed[key]
        if isinstance(expected, set):
            if value not in expected:
                raise ValueError(f"invalid {key}")
        elif type(value) is not expected:
            raise ValueError(f"{key} must be {expected.__name__}")
    if operation == "backup" and not 0 <= values["image_size"] <= 4_194_304:
        raise ValueError("image_size must be between 0 and 4194304 MiB")
    return values


def _image_name(selection: dict[str, Any], fallback: str) -> str:
    value = selection.get("image_name", fallback)
    if not isinstance(value, str) or not _IMAGE_NAME.fullmatch(value):
        raise ValueError("image name must contain only safe filename characters")
    return value


def build_draft(operation: str | JobDraft, selection: dict[str, Any] | None = None) -> PublicJobSpec:
    """Build the public immutable specification from the central typed draft.

    The mapping form remains for command-line callers and existing tests.
    """
    if isinstance(operation, JobDraft):
        draft = operation
        operation = draft.operation
        selection = {"source": draft.source, "destination": draft.destination,
                     "destinations": draft.destinations, "image_name": draft.image_name,
                     "options": draft.option_values()}
        if draft.repository is not None:
            selection["destination"] = draft.repository
    selection = selection or {}
    source = selection.get("source")
    destination = selection.get("destination")
    destinations = selection.get("destinations", ())
    if source is None or (destination is None and not (operation == "restore" and destinations)):
        raise ValueError("source and destination are required")
    job_id = str(uuid4())
    if operation == "backup":
        identity = getattr(source, "identity", None)
        if identity is None:
            raise ValueError("source device has no stable identity")
        repository = Path(destination)
        kind = JobOperation.SAVEPARTS if identity.device_type == "part" else JobOperation.SAVEDISK
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        options = _options(operation, selection)
        if options["encrypt"] and identity.device_type != "disk":
            raise ValueError("Clonezilla does not expose safe topology for encrypted partition backups")
        capabilities = selection.get("capabilities")
        if options["encrypt"] and capabilities is not None and not capabilities.supports("ecryptfs"):
            raise ValueError("encrypted backup requires ecryptfs")
        if capabilities is not None:
            engine_binary = {"partclone": "partclone", "dd": "dd", "ntfsclone": "ntfsclone"}[options["engine"]]
            if not capabilities.supports(engine_binary):
                raise ValueError(f"backup engine requires {engine_binary}")
            compressor_tools = {"gzip": {"gzip", "pigz"}, "bzip2": {"bzip2", "pbzip2"}, "xz": {"xz", "pixz"}, "lzma": {"lzma"},
                                "lz4": {"lz4", "lz4mt"}, "lzo": {"lzop"}, "lzip": {"lzip", "plzip"},
                                "zstd": {"zstd", "zstdmt"}, "lrzip": {"lrzip"}}
            tools = compressor_tools.get(options["compression"], set())
            if tools and not tools & capabilities.compressors:
                raise ValueError(f"compression requires one of: {', '.join(sorted(tools))}")
        image_name = _image_name(selection, f"transume-{timestamp}")
        if (repository / image_name).exists():
            raise ValueError("an image with this name already exists")
        return PublicJobSpec(
            job_id=job_id,
            operation=kind,
            sources=(identity,),
            repository=str(repository),
            image_name=image_name,
            options={key: value for key, value in options.items()
                     if key != "post_action" and (key != "source_partition" or value)},
            required_capabilities=("ecryptfs",) if options["encrypt"] else (),
            risk="write-image",
            post_action=options["post_action"],
        )
    if operation == "restore":
        identities = tuple(getattr(value, "identity", None) for value in destinations or (destination,))
        if any(value is None for value in identities):
            raise ValueError("image and destination identities are required")
        image = parse_clonezilla_image(source) if isinstance(source, Path) else source
        if not isinstance(image, ImageCandidate):
            raise ValueError("restore source must be a Clonezilla image")
        options = _options(operation, selection)
        if image.status in {ImageStatus.INCOMPLETE, ImageStatus.UNSUPPORTED}:
            raise ValueError(f"image cannot be restored: {image.status}")
        if image.status is ImageStatus.ENCRYPTED:
            if not image.topology.disks or (image.image_type is ImageType.SAVEPARTS and not image.topology.partitions):
                raise ValueError("encrypted image topology is unsupported")
        # This is image evidence, not a user-selectable restore behavior.
        options["encrypted"] = image.status is ImageStatus.ENCRYPTED
        if (image.status is ImageStatus.NEEDS_VERIFICATION or image.checksums) and not options["check_image"]:
            raise ValueError("image requires verification before restore")
        image_path = image.path
        if not identities or not image_path.name:
            raise ValueError("image and destination identity are required")
        if image.image_type is ImageType.SAVEDISK and any(identity.device_type != "disk" for identity in identities):
            raise ValueError("a full-disk image requires a disk destination")
        if image.image_type is ImageType.SAVEPARTS and any(identity.device_type != "part" for identity in identities):
            raise ValueError("a partition image requires a partition destination")
        if image.image_type is ImageType.UNKNOWN:
            raise ValueError("image topology is unsupported")
        expected = len(image.topology.disks) if image.image_type is ImageType.SAVEDISK else len(image.topology.partitions)
        source_partition = options.get("source_partition", "")
        if (image.image_type is ImageType.SAVEPARTS and not source_partition
                and len(image.source_partitions) == 1):
            source_partition = image.source_partitions[0]
            options["source_partition"] = source_partition
        if image.image_type is ImageType.SAVEDISK and source_partition:
            raise ValueError("source_partition is valid only for partition images")
        if image.image_type is ImageType.SAVEPARTS:
            # A partition-scoped restore must never rewrite disk-wide metadata.
            options.update({"partition_table": "existing", "restore_mbr": False,
                            "restore_ebr": False, "hidden_data": False,
                            "update_efi": False})
        if source_partition:
            if source_partition not in image.source_partitions:
                raise ValueError("selected source partition is not present in the image")
            expected = 1
        if len(identities) != expected:
            raise ValueError("every source disk requires an explicit destination mapping")
        if len({identity.path for identity in identities}) != len(identities):
            raise ValueError("restore targets must be unique")
        if image.image_type is ImageType.SAVEDISK:
            for source_disk, target in zip(image.topology.disks, identities):
                if source_disk.size is not None and target.size < source_disk.size:
                    raise ValueError(f"destination is smaller than source disk {source_disk.name}")
        else:
            selected = ([next(part for part in image.topology.partitions
                              if part.name == source_partition)] if source_partition
                        else list(image.topology.partitions))
            for source_part, target in zip(selected, identities):
                if source_part.size is not None and target.size < source_part.size:
                    raise ValueError(f"destination is smaller than source partition {source_part.name}")
        # Without -f, Clonezilla supports only corresponding partition names.
        if (image.image_type is ImageType.SAVEPARTS and not source_partition
                and tuple(Path(identity.path).name for identity in identities) != image.source_partitions):
            raise ValueError("multi-partition restore requires corresponding target partition names")
        kind = JobOperation.RESTOREPARTS if identities[0].device_type == "part" else JobOperation.RESTOREDISK
        return PublicJobSpec(
            job_id=job_id,
            operation=kind,
            destinations=identities,
            repository=str(image_path.parent),
            image_name=image_path.name,
            image_fingerprint=image_fingerprint(image_path),
            options={key: value for key, value in options.items()
                     if key != "post_action" and (key != "source_partition" or value)},
            required_capabilities=("lvm",) if image.lvm.volume_groups else (),
            risk="destructive",
            post_action=options["post_action"],
        )
    if operation == "clone":
        source_identity = getattr(source, "identity", None)
        destination_identity = getattr(destination, "identity", None)
        if source_identity is None or destination_identity is None:
            raise ValueError("source and destination identities are required")
        if source_identity.device_type != destination_identity.device_type:
            raise ValueError("source and destination must both be disks or both be partitions")
        if source_identity.path == destination_identity.path:
            raise ValueError("source and destination must be different devices")
        if destination_identity.size < source_identity.size:
            raise ValueError("destination is smaller than source")
        kind = JobOperation.CLONE_PART if source_identity.device_type == "part" else JobOperation.CLONE_DISK
        options = _options(operation, selection)
        return PublicJobSpec(
            job_id=job_id,
            operation=kind,
            sources=(source_identity,),
            destinations=(destination_identity,),
            options={key: value for key, value in options.items() if key != "post_action"},
            risk="destructive",
            post_action=options["post_action"],
        )
    raise ValueError("unsupported draft operation")


def build_image_action(action: str, image: ImageCandidate, options: dict[str, Any] | None = None) -> PublicJobSpec:
    """Build an image-only action from a freshly discovered candidate."""
    if not isinstance(image, ImageCandidate) or not image.path.name:
        raise ValueError("select a Clonezilla image")
    if image.status in {ImageStatus.INCOMPLETE, ImageStatus.UNSUPPORTED}:
        raise ValueError(f"image cannot be used: {image.status}")
    kinds = {"check": JobOperation.CHECK_IMAGE}
    try:
        operation = kinds[action]
    except KeyError:
        raise ValueError("unsupported image action") from None
    values = dict(options or {})
    if action == "check" and values:
        raise ValueError("image check does not accept options")
    return PublicJobSpec(str(uuid4()), operation, repository=str(image.path.parent),
                           image_name=image.path.name, image_fingerprint=image_fingerprint(image.path), options=values,
                           risk="read-only")
