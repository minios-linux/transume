"""Shared conservative preflight checks for planning and execution."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Iterable

from .domain import DeviceIdentity, JobOperation, PublicJobSpec
from .draft import ImagePreflightContext, image_fingerprint
from .images import ImageProblemCode, ImageStatus, parse_clonezilla_image
from .clonezilla import build_command


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class PreflightIssue:
    code: str
    severity: Severity
    message: str
    subject: str | None = None


@dataclass(frozen=True, slots=True)
class PreflightReport:
    issues: tuple[PreflightIssue, ...] = ()

    @property
    def ok(self) -> bool:
        return not any(issue.severity is Severity.ERROR for issue in self.issues)

    def require_ok(self) -> None:
        if not self.ok:
            raise ValueError(next(issue.message for issue in self.issues if issue.severity is Severity.ERROR))


class PreflightService:
    def __init__(self, *, binaries: Callable[[str], bool] = shutil.which,
                 device_state: Callable[[], Iterable[object]] | None = None,
                 repository_device: Callable[[Path], str | None] | None = None,
                 disk_usage: Callable[[Path], object] = shutil.disk_usage) -> None:
        self.binaries, self.device_state, self.repository_device = binaries, device_state, repository_device
        self.disk_usage = disk_usage

    def check(self, spec: PublicJobSpec, *, image_context: ImagePreflightContext | None = None) -> PreflightReport:
        issues: list[PreflightIssue] = []
        def add(code: str, severity: Severity, message: str, subject: str | None = None) -> None:
            issues.append(PreflightIssue(code, severity, message, subject))
        if spec.operation in {JobOperation.RESTOREDISK, JobOperation.RESTOREPARTS}:
            self._restore(spec, image_context, add)
        try:
            command_path = build_command(spec).argv[0]
        except ValueError as exc:
            add("job-invalid", Severity.ERROR, str(exc))
            return PreflightReport(tuple(issues))
        binary = Path(command_path).name
        # Internal adapters are intentionally installed outside PATH and are
        # always executed by absolute path.  Keep the name fallback for injected
        # capability services used by callers and tests.
        if self.binaries(command_path) is None and self.binaries(binary) is None:
            add("binary-missing", Severity.ERROR, f"Required binary was not found: {binary}", binary)
        for capability in spec.required_capabilities:
            if self.binaries(capability) is None:
                add("capability-missing", Severity.ERROR, f"Required capability was not found: {capability}", capability)
        all_devices = (*spec.sources, *spec.destinations)
        paths = [device.path for device in all_devices]
        if len(set(paths)) != len(paths): add("duplicate-device", Severity.ERROR, "Sources and targets must be unique")
        for source in spec.sources:
            for target in spec.destinations:
                if self._related(source, target): add("device-relationship", Severity.ERROR, "Source and target overlap in the device graph", target.path)
        self._repository(spec, add)
        self._capacity(spec, add)
        self._device_states(spec, add)
        if self.repository_device and spec.repository and spec.operation in {JobOperation.SAVEDISK, JobOperation.SAVEPARTS}:
            backing = self.repository_device(Path(spec.repository))
            if backing is None: add("repository-backing-unknown", Severity.WARNING, "Repository backing device could not be determined")
            elif any(backing == source.path for source in spec.sources): add("repository-source-collision", Severity.ERROR, "Repository is backed by the backup source", backing)
        return PreflightReport(tuple(issues))

    @staticmethod
    def _related(left: DeviceIdentity, right: DeviceIdentity) -> bool:
        return left.path == right.path or left.path in right.parent_chain or right.path in left.parent_chain or bool(set(left.relationships) & ({right.path, *right.parent_chain, *right.relationships}))

    def _repository(self, spec, add) -> None:
        if not spec.repository: return
        root = Path(spec.repository)
        try:
            resolved = root.resolve(strict=True)
        except OSError:
            add("repository-unavailable", Severity.ERROR, "Repository is unavailable", str(root)); return
        if root.is_symlink() or not resolved.is_dir(): add("repository-unsafe", Severity.ERROR, "Repository must be a real directory", str(root)); return
        if spec.operation in {
            JobOperation.SAVEDISK, JobOperation.SAVEPARTS,
        }:
            if not os.access(resolved, os.W_OK): add("repository-not-writable", Severity.ERROR, "Backup repository is not writable", str(resolved))
            required = sum(source.size for source in spec.sources)
            try:
                free = self.disk_usage(resolved).free
            except (OSError, AttributeError):
                add("repository-capacity-unavailable", Severity.ERROR,
                    "Backup repository capacity is unavailable", str(resolved))
            else:
                if required <= 0:
                    add("source-size-unknown", Severity.WARNING, "Backup source size is unknown")
                elif free < required:
                    add("repository-space-insufficient", Severity.ERROR,
                        "Backup repository has insufficient free space", str(resolved))
        if spec.operation in {JobOperation.SAVEDISK, JobOperation.SAVEPARTS}:
            if spec.image_name and (resolved / spec.image_name).exists(): add("image-exists", Severity.ERROR, "Backup image directory already exists", spec.image_name)

    def _restore(self, spec, context, add) -> None:
        assert spec.repository and spec.image_name
        root, image = Path(spec.repository), Path(spec.repository) / spec.image_name
        try:
            canonical_root, canonical_image = root.resolve(strict=True), image.resolve(strict=True)
            canonical_image.relative_to(canonical_root)
        except (OSError, ValueError):
            add("image-escape", Severity.ERROR, "Image is outside its repository or unavailable", str(image)); return
        parsed = parse_clonezilla_image(canonical_image)
        source_partition = spec.options.get("source_partition", "")
        if source_partition and parsed.image_type.value != "saveparts":
            add("restore-source-partition-invalid", Severity.ERROR,
                "A source partition can be selected only from a partition image", str(source_partition))
        if source_partition and source_partition not in parsed.source_partitions:
            add("restore-source-partition-missing", Severity.ERROR,
                "Selected source partition is not present in the image", str(source_partition))
        expected = (1 if source_partition else
                    len(parsed.topology.disks) if parsed.image_type.value == "savedisk"
                    else len(parsed.topology.partitions))
        if len(spec.destinations) != expected:
            add("restore-target-count", Severity.ERROR,
                "Restore targets do not match the image topology", str(image))
        encrypted_ok = (parsed.status is ImageStatus.ENCRYPTED and spec.options.get("encrypted") is True
                        and bool(parsed.topology.disks))
        if parsed.status in {ImageStatus.INCOMPLETE, ImageStatus.DAMAGED, ImageStatus.UNSUPPORTED} or (parsed.status is ImageStatus.ENCRYPTED and not encrypted_ok):
            add("image-invalid", Severity.ERROR, f"Image cannot be restored: {parsed.status}", str(image))
        if any(warning.code is ImageProblemCode.UNSUPPORTED_METADATA
               and warning.message.startswith("LVM metadata")
               for warning in parsed.metadata_warnings):
            add("image-lvm-metadata-invalid", Severity.ERROR,
                "Image contains incomplete or malformed LVM metadata", str(image))
        if spec.image_fingerprint is None:
            add("image-evidence-missing", Severity.ERROR, "Image selection evidence is missing", str(image))
        else:
            try: changed = image_fingerprint(canonical_image) != spec.image_fingerprint
            except (OSError, ValueError): changed = True
            if changed: add("image-changed", Severity.ERROR, "Image changed after it was selected", str(image))
        if context is not None:
            try: changed = context.path.resolve(strict=True) != canonical_image or image_fingerprint(canonical_image) != context.fingerprint
            except (OSError, ValueError): changed = True
            if changed: add("image-changed", Severity.ERROR, "Image changed after it was selected", str(image))
        if parsed.image_type.value == "savedisk":
            for source in parsed.topology.disks:
                if not parsed.encrypted and source.partition_table is None:
                    add("image-partition-table-missing", Severity.ERROR,
                        "Image partition table metadata is missing", source.name)
            for source, target in zip(parsed.topology.disks, spec.destinations):
                if source.size is None:
                    add("source-size-unknown", Severity.WARNING, "Image source disk size is unknown", source.name)
                elif target.size < source.size:
                    add("target-too-small", Severity.ERROR, "Target is smaller than image source disk", target.path)
        elif parsed.image_type.value == "saveparts":
            selected = ([next((part for part in parsed.topology.partitions
                               if part.name == source_partition), None)] if source_partition
                        else list(parsed.topology.partitions))
            for source, target in zip((part for part in selected if part is not None), spec.destinations):
                if source.size is None:
                    add("source-size-unknown", Severity.WARNING, "Source partition size is unknown", source.name)
                elif target.size < source.size:
                    add("target-too-small", Severity.ERROR, "Target is smaller than image source partition", target.path)
            if (not source_partition
                    and tuple(Path(target.path).name for target in spec.destinations) != parsed.source_partitions):
                add("restore-partition-mapping-ambiguous", Severity.ERROR,
                    "Partition targets must correspond to image partition names and order")

    def _capacity(self, spec, add) -> None:
        if spec.operation in {JobOperation.CLONE_DISK, JobOperation.CLONE_PART}:
            pairs = zip(spec.sources, spec.destinations)
            for source, target in pairs:
                if source.size <= 0: add("source-size-unknown", Severity.WARNING, "Source size is unknown", source.path)
                elif target.size < source.size:
                    add("target-too-small", Severity.ERROR, "Target is smaller than source", target.path)
        # Restore topology sizes are only known from reparsing and are checked above by callers that have it.

    def _device_states(self, spec, add) -> None:
        if self.device_state is None: return
        current = {getattr(value, "path", None): value for value in self.device_state()}
        for target in spec.destinations:
            value = current.get(target.path)
            if value is None: add("device-state-unknown", Severity.WARNING, "Current target state is unavailable", target.path); continue
            for attribute, code, message in (("is_mounted", "target-mounted", "Target is mounted"), ("is_swap", "target-swap", "Target is active swap"), ("is_system", "target-system", "Target is a system device"), ("is_live", "target-live", "Target is live media"), ("read_only", "target-read-only", "Target is read-only")):
                if getattr(value, attribute, False): add(code, Severity.ERROR, message, target.path)
