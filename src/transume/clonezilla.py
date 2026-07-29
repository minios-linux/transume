"""Typed, shell-free Clonezilla command construction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .domain import JobOperation, PublicJobSpec

OCS_SR = "/usr/sbin/ocs-sr"
OCS_ONTHEFLY = "/usr/sbin/ocs-onthefly"
OCS_CHKIMG = "/usr/sbin/ocs-chkimg"
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DEVICE = re.compile(r"/dev/[A-Za-z0-9._/+:-]+\Z")
_PARTITION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")

_SAVE_OPTIONS: dict[str, dict[Any, tuple[str, ...]]] = {
    "compression": {
        "none": ("-z0",), "gzip": ("-z1p",), "bzip2": ("-z2p",),
        "lzo": ("-z3",), "lzma": ("-z4",), "xz": ("-z5p",), "lzip": ("-z6p",),
        "lrzip": ("-z7",), "lz4": ("-z8p",), "zstd": ("-z9p",),
    },
    "engine": {
        "partclone": ("-q2",), "dd": ("-q1",), "ntfsclone": ("-q",),
    },
    "filesystem_check": {
        "skip": ("-sfsck",), "check": ("-fsck",), "repair": ("-fsck-y",),
    },
    "checksum": {
        "none": (), "md5": ("-gm",), "sha1": ("-gs",), "files": ("-gmf",),
    },
}

_RESTORE_OPTIONS: dict[str, dict[Any, tuple[str, ...]]] = {
    "partition_table": {
        "original": ("-k0",), "proportional": ("-k1",), "existing": ("-k",),
    },
    "grub": {"none": (), "auto": ("-g", "auto")},
}


@dataclass(frozen=True, slots=True)
class Command:
    argv: tuple[str, ...]
    destructive: bool
    environment: tuple[tuple[str, str], ...] = (("LC_ALL", "C"), ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"))
    cwd: str | None = None


def build_command(spec: PublicJobSpec) -> Command:
    for device in (*spec.sources, *spec.destinations):
        if not _DEVICE.fullmatch(device.path):
            raise ValueError("invalid device path")
    operation = spec.operation
    if operation in {JobOperation.SAVEDISK, JobOperation.SAVEPARTS}:
        if spec.destinations or not spec.repository or not spec.image_name or not _IMAGE.fullmatch(spec.image_name):
            raise ValueError("save requires repository, safe image name, sources, and no device destinations")
        options = _build_save_options(spec.options)
        argv = (OCS_SR, "-batch", "-nogui", "-or", _repository(spec.repository),
                *options, "-p", _post_action(spec.post_action), operation.value, spec.image_name,
                *(x.path.removeprefix("/dev/") for x in spec.sources))
        destructive = False
    elif operation in {JobOperation.RESTOREDISK, JobOperation.RESTOREPARTS}:
        if spec.sources or not spec.destinations or not spec.repository or not spec.image_name or not _IMAGE.fullmatch(spec.image_name):
            raise ValueError("restore requires an image and device destinations")
        restore_options = dict(spec.options)
        if operation is JobOperation.RESTOREPARTS:
            partition_safe = {"partition_table": "existing", "restore_mbr": False,
                              "restore_ebr": False, "hidden_data": False,
                              "update_efi": False}
            if any(key in restore_options and restore_options[key] != value
                   for key, value in partition_safe.items()):
                raise ValueError("restoreparts cannot rewrite disk-wide metadata")
            restore_options.update(partition_safe)
        source_partition = restore_options.get("source_partition")
        if source_partition and (operation is not JobOperation.RESTOREPARTS
                                 or len(spec.destinations) != 1):
            raise ValueError("source_partition requires one restoreparts destination")
        options = _build_restore_options(restore_options)
        argv = (OCS_SR, "-batch", "-nogui", "-or", _repository(spec.repository),
                  *options, "-p", _post_action(spec.post_action),
                 operation.value, spec.image_name, *(x.path.removeprefix("/dev/") for x in spec.destinations))
        destructive = True
    elif operation in {JobOperation.CLONE_DISK, JobOperation.CLONE_PART}:
        if len(spec.sources) != 1 or len(spec.destinations) != 1:
            raise ValueError("direct clone requires exactly one source and destination")
        if spec.sources[0].path == spec.destinations[0].path:
            raise ValueError("source and destination must differ")
        options = _build_clone_options(spec.options)
        argv = (OCS_ONTHEFLY, "-batch", "-nogui", "--postaction", _post_action(spec.post_action), *options,
                "-f", spec.sources[0].path, "-d", spec.destinations[0].path)
        destructive = True
    elif operation is JobOperation.CHECK_IMAGE:
        if spec.sources or spec.destinations or not spec.repository or not spec.image_name or not _IMAGE.fullmatch(spec.image_name):
            raise ValueError("image check requires only a repository and image name")
        if spec.options:
            raise ValueError("image check does not accept options")
        argv = (OCS_CHKIMG, "-b", "-nogui", "-or", _repository(spec.repository), spec.image_name)
        destructive = False
    else:
        raise ValueError("unsupported operation")
    return Command(tuple(argv), destructive)


def _repository(value: str) -> str:
    path = Path(value)
    if not path.is_absolute() or "\x00" in value:
        raise ValueError("repository must be an absolute path")
    return str(path)


def _post_action(value: str) -> str:
    # Explicit true prevents Clonezilla from dropping into an interactive prompt.
    return "true" if value == "none" else value


def _mapped_options(options: Mapping[str, Any], schema: dict[str, dict[Any, tuple[str, ...]]]) -> list[str]:
    result: list[str] = []
    for key, value in options.items():
        choices = schema.get(key)
        if choices is None or value not in choices:
            raise ValueError(f"unsupported value for {key}")
        result.extend(choices[value])
    return result


def _build_save_options(options: Mapping[str, Any]) -> tuple[str, ...]:
    simple = {key: value for key, value in options.items() if key in _SAVE_OPTIONS}
    result = _mapped_options(simple, _SAVE_OPTIONS)
    for key, flag in (("rescue", "-rescue"), ("verify_image", "-sc")):
        if key in options:
            if not isinstance(options[key], bool):
                raise ValueError(f"{key} must be boolean")
            # Clonezilla's -sc means skip the default restorable-image check.
            if key == "rescue" and options[key]:
                result.append(flag)
            elif key == "verify_image" and not options[key]:
                result.append(flag)
    if options.get("encrypt") is True:
        result.append("-enc")
    elif "encrypt" in options and not isinstance(options["encrypt"], bool):
        raise ValueError("encrypt must be boolean")
    if "image_size" in options and options["image_size"] != 0:
        size = options["image_size"]
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 4_194_304:
            raise ValueError("image_size must be between 1 and 4194304 MiB")
        result.extend(("-i", str(size)))
    allowed = set(_SAVE_OPTIONS) | {"rescue", "verify_image", "image_size", "encrypt"}
    if set(options) - allowed:
        raise ValueError("unsupported save option")
    return tuple(result)


def _build_restore_options(options: Mapping[str, Any]) -> tuple[str, ...]:
    simple = {key: value for key, value in options.items() if key in _RESTORE_OPTIONS}
    result = _mapped_options(simple, _RESTORE_OPTIONS)
    flags = {
        "resize": ("-r", False),
        "check_image": ("-scr", True),
        "restore_mbr": ("-t", True),
        "restore_ebr": ("-t2", True),
        "hidden_data": ("-j2", False),
        "update_efi": ("-iefi", True),
    }
    for key, (flag, inverted) in flags.items():
        if key not in options:
            continue
        value = options[key]
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be boolean")
        if value is not inverted:
            result.append(flag)
    if options.get("encrypted") is True:
        result.append("-enc")
    elif "encrypted" in options and not isinstance(options["encrypted"], bool):
        raise ValueError("encrypted must be boolean")
    source_partition = options.get("source_partition")
    if source_partition:
        if not isinstance(source_partition, str) or not _PARTITION.fullmatch(source_partition):
            raise ValueError("invalid source_partition")
        result.extend(("-f", source_partition))
    elif "source_partition" in options and not isinstance(source_partition, str):
        raise ValueError("source_partition must be a string")
    allowed = set(_RESTORE_OPTIONS) | set(flags) | {"encrypted", "source_partition"}
    if set(options) - allowed:
        raise ValueError("unsupported restore option")
    return tuple(result)


def _build_clone_options(options: Mapping[str, Any]) -> tuple[str, ...]:
    flags = {
        "resize": "-r", "rescue": "-rescue", "direct_io": "-edio",
        "force_dd": "-q1", "hidden_data": "-j2",
    }
    result = []
    for key, value in options.items():
        if key not in flags or not isinstance(value, bool):
            raise ValueError("unsupported direct-clone option")
        if value:
            result.append(flags[key])
    return tuple(result)
