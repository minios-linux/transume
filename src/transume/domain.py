"""Immutable public domain objects shared across the privilege boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


class JobOperation(StrEnum):
    SAVEDISK = "savedisk"
    SAVEPARTS = "saveparts"
    RESTOREDISK = "restoredisk"
    RESTOREPARTS = "restoreparts"
    CLONE_DISK = "clone-disk"
    CLONE_PART = "clone-part"
    CHECK_IMAGE = "check-image"


def _text(value: object, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    path: str
    sysfs_path: str
    major_minor: str
    device_type: str
    size: int
    parent_chain: tuple[str, ...] = ()
    wwn: str | None = None
    serial: str | None = None
    by_id: tuple[str, ...] = ()
    vendor: str | None = None
    model: str | None = None
    partition_table_type: str | None = None
    partition_table_uuid: str | None = None
    partition_uuids: tuple[tuple[str, str], ...] = ()
    relationships: tuple[str, ...] = ()
    removable: bool = False
    transport: str | None = None

    def __post_init__(self) -> None:
        for name in ("path", "sysfs_path", "major_minor", "device_type"):
            _text(getattr(self, name), name)
        if not self.path.startswith("/dev/") or not self.sysfs_path.startswith("/sys/"):
            raise ValueError("device and sysfs paths must be absolute")
        if self.size < 0:
            raise ValueError("size must not be negative")
        if not (self.wwn or self.serial or self.by_id):
            raise ValueError("at least one stable device identifier is required")

    def to_dict(self, *, redacted: bool = False) -> dict[str, Any]:
        value = {
            "path": self.path, "sysfs_path": self.sysfs_path,
            "major_minor": self.major_minor, "device_type": self.device_type,
            "size": self.size, "parent_chain": list(self.parent_chain),
            "wwn": self.wwn, "serial": self.serial, "by_id": list(self.by_id),
            "vendor": self.vendor, "model": self.model,
            "partition_table_type": self.partition_table_type,
            "partition_table_uuid": self.partition_table_uuid,
            "partition_uuids": [list(item) for item in self.partition_uuids],
            "relationships": list(self.relationships), "removable": self.removable,
            "transport": self.transport,
        }
        if redacted:
            value["wwn"] = _redact(self.wwn)
            value["serial"] = _redact(self.serial)
            value["by_id"] = []
            value["partition_table_uuid"] = _redact(self.partition_table_uuid)
            value["partition_uuids"] = []
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DeviceIdentity:
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        if set(value) - allowed:
            raise ValueError("unknown DeviceIdentity fields")
        data = dict(value)
        for name in ("parent_chain", "by_id", "relationships"):
            data[name] = tuple(data.get(name, ()))
        data["partition_uuids"] = tuple(tuple(x) for x in data.get("partition_uuids", ()))
        return cls(**data)


def _redact(value: str | None) -> str | None:
    return None if value is None else "***" + value[-4:]


@dataclass(frozen=True, slots=True)
class PublicJobSpec:
    job_id: str
    operation: JobOperation
    sources: tuple[DeviceIdentity, ...] = ()
    destinations: tuple[DeviceIdentity, ...] = ()
    repository: str | None = None
    image_name: str | None = None
    image_fingerprint: str | None = None
    options: Mapping[str, str | bool | int] = field(default_factory=dict)
    required_capabilities: tuple[str, ...] = ()
    risk: str = "destructive"
    post_action: str = "none"

    def __post_init__(self) -> None:
        _text(self.job_id, "job_id")
        needs_device_source = self.operation in {
            JobOperation.SAVEDISK,
            JobOperation.SAVEPARTS,
            JobOperation.CLONE_DISK,
            JobOperation.CLONE_PART,
        }
        if needs_device_source and not self.sources:
            raise ValueError("operation requires at least one device source")
        if self.operation in {
            JobOperation.RESTOREDISK,
            JobOperation.RESTOREPARTS,
            JobOperation.CHECK_IMAGE,
        } and self.sources:
            raise ValueError("image operations do not accept a device source")
        if self.risk not in {"read-only", "write-image", "destructive"}:
            raise ValueError("invalid risk")
        if self.post_action not in {"none", "poweroff", "reboot"}:
            raise ValueError("invalid post action")
        if self.repository is not None:
            _text(self.repository, "repository")
        if self.image_name is not None:
            _text(self.image_name, "image_name")
        if self.image_fingerprint is not None:
            if (not isinstance(self.image_fingerprint, str) or len(self.image_fingerprint) != 64
                    or any(character not in "0123456789abcdef" for character in self.image_fingerprint)):
                raise ValueError("image_fingerprint must be a SHA-256 hex digest")
        clean = dict(self.options)
        if any(not isinstance(k, str) or not isinstance(v, (str, bool, int)) for k, v in clean.items()):
            raise ValueError("options must contain scalar public values")
        forbidden = {"password", "passphrase", "token", "private_key", "secret"}
        if any(any(word in k.lower() for word in forbidden) for k in clean):
            raise ValueError("secrets are forbidden in PublicJobSpec")
        object.__setattr__(self, "options", MappingProxyType(clean))

    def to_dict(self, *, redacted: bool = False) -> dict[str, Any]:
        return {"job_id": self.job_id, "operation": self.operation.value,
                "sources": [x.to_dict(redacted=redacted) for x in self.sources],
                "destinations": [x.to_dict(redacted=redacted) for x in self.destinations],
                "repository": self.repository, "image_name": self.image_name,
                "image_fingerprint": self.image_fingerprint,
                "options": dict(self.options),
                "required_capabilities": list(self.required_capabilities),
                "risk": self.risk, "post_action": self.post_action}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PublicJobSpec:
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        if set(value) != allowed:
            raise ValueError("missing or unknown PublicJobSpec fields")
        data = dict(value)
        data["operation"] = JobOperation(data["operation"])
        data["sources"] = tuple(DeviceIdentity.from_dict(x) for x in data["sources"])
        data["destinations"] = tuple(DeviceIdentity.from_dict(x) for x in data["destinations"])
        data["required_capabilities"] = tuple(data["required_capabilities"])
        return cls(**data)
