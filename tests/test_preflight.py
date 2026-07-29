from pathlib import Path
from types import SimpleNamespace

import pytest

from transume.domain import DeviceIdentity, JobOperation, PublicJobSpec
from transume.draft import ImagePreflightContext, image_fingerprint
from transume.preflight import PreflightService, Severity
from transume.runner import RunnerValidationError, run_job


def device(path: str, size: int = 1000, *, parents=(), relationships=()):
    return DeviceIdentity(path, f"/sys/class/block/{Path(path).name}", "8:0", "disk", size,
                          serial=path, parent_chain=parents, relationships=relationships)


def test_preflight_reports_duplicate_and_graph_collision(tmp_path):
    source, target = device("/dev/sda", relationships=("/dev/sdb",)), device("/dev/sdb")
    spec = PublicJobSpec("job", JobOperation.CLONE_DISK, (source,), (target,),
                         options={"resize": False}, risk="destructive")
    report = PreflightService(binaries=lambda _: "yes").check(spec)
    assert {issue.code for issue in report.issues} >= {"device-relationship"}
    assert not report.ok


def test_clone_smaller_target_is_blocked_even_with_resize():
    spec = PublicJobSpec(
        "job", JobOperation.CLONE_DISK, (device("/dev/sda", 2000),),
        (device("/dev/sdb", 1000),), options={"resize": True}, risk="destructive",
    )
    report = PreflightService(binaries=lambda _: "yes").check(spec)
    assert any(issue.code == "target-too-small" and issue.severity is Severity.ERROR
               for issue in report.issues)


def test_backup_with_insufficient_repository_space_is_blocked(tmp_path):
    spec = PublicJobSpec(
        "job", JobOperation.SAVEDISK, (device("/dev/sda", 2000),),
        repository=str(tmp_path), image_name="backup", risk="write-image",
    )
    report = PreflightService(
        binaries=lambda _: "yes",
        disk_usage=lambda _path: SimpleNamespace(free=1999),
    ).check(spec)

    assert any(issue.code == "repository-space-insufficient"
               and issue.severity is Severity.ERROR for issue in report.issues)


def test_restore_mutation_is_a_structured_error(tmp_path):
    image = tmp_path / "image"; image.mkdir()
    (image / "parts").write_text("sda1\n")
    (image / "disk").write_text("sda\n")
    (image / "sda1.ext4-ptcl-img").write_bytes(b"data")
    context = ImagePreflightContext(image, image_fingerprint(image))
    spec = PublicJobSpec("job", JobOperation.RESTOREDISK, destinations=(device("/dev/sdb"),),
                         repository=str(tmp_path), image_name="image", options={"resize": False}, risk="destructive")
    (image / "sda1.ext4-ptcl-img").write_bytes(b"changed")
    report = PreflightService(binaries=lambda _: "yes").check(spec, image_context=context)
    assert any(issue.code == "image-changed" and issue.severity is Severity.ERROR for issue in report.issues)


def test_restore_reparse_requires_exact_destination_count(tmp_path):
    image = tmp_path / "image"; image.mkdir()
    (image / "parts").write_text("sda1\n")
    (image / "disk").write_text("sda\n")
    (image / "sda1.ext4-ptcl-img").write_bytes(b"data")
    spec = PublicJobSpec("job", JobOperation.RESTOREDISK, destinations=(), repository=str(tmp_path),
                         image_name="image", image_fingerprint=image_fingerprint(image), options={}, risk="destructive")
    report = PreflightService(binaries=lambda _: "yes").check(spec)
    assert any(issue.code == "restore-target-count" and issue.severity is Severity.ERROR for issue in report.issues)


def test_savedisk_restore_requires_partition_table_metadata(tmp_path):
    image = tmp_path / "image"; image.mkdir()
    (image / "parts").write_text("sda1\n")
    (image / "disk").write_text("sda\n")
    (image / "sda1.ext4-ptcl-img").write_bytes(b"data")
    spec = PublicJobSpec(
        "job", JobOperation.RESTOREDISK, destinations=(device("/dev/sdb"),),
        repository=str(tmp_path), image_name="image",
        image_fingerprint=image_fingerprint(image), options={}, risk="destructive",
    )

    report = PreflightService(binaries=lambda _: "yes").check(spec)

    assert any(issue.code == "image-partition-table-missing"
               and issue.severity is Severity.ERROR for issue in report.issues)


def test_restore_rejects_partial_lvm_metadata(tmp_path):
    image = tmp_path / "image"; image.mkdir()
    (image / "parts").write_text("sda1\n")
    (image / "disk").write_text("sda\n")
    (image / "sda-pt.sf").write_text("/dev/sda1 : start=2048, size=4096\n")
    (image / "sda1.ext4-ptcl-img").write_bytes(b"data")
    (image / "lvm_vg_dev.list").write_text("invalid\n")
    (image / "lvm_logv.list").write_text("/dev/vg/root  ext4 data\n")
    spec = PublicJobSpec(
        "job", JobOperation.RESTOREDISK, destinations=(device("/dev/sdb", 4096 * 512),),
        repository=str(tmp_path), image_name="image",
        image_fingerprint=image_fingerprint(image), options={}, risk="destructive",
    )

    report = PreflightService(binaries=lambda _: "yes").check(spec)

    assert any(issue.code == "image-lvm-metadata-invalid"
               and issue.severity is Severity.ERROR for issue in report.issues)


def test_execute_rejects_crafted_restore_with_extra_target_before_spawn(tmp_path):
    image = tmp_path / "image"; image.mkdir()
    (image / "parts").write_text("sda1\n")
    (image / "disk").write_text("sda\n")
    (image / "sda1.ext4-ptcl-img").write_bytes(b"data")
    destinations = (device("/dev/sdb"), device("/dev/sdc"))
    spec = PublicJobSpec("job", JobOperation.RESTOREDISK, destinations=destinations, repository=str(tmp_path),
                         image_name="image", image_fingerprint=image_fingerprint(image), options={}, risk="destructive")
    spawned = []
    with pytest.raises(RunnerValidationError, match="targets do not match"):
        run_job(spec, authorized=True, resolve_identity=lambda value: value,
                execute=lambda *args, **kwargs: spawned.append(args),
                preflight_service=PreflightService(binaries=lambda _: "yes"))
    assert not spawned
