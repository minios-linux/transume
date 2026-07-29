from dataclasses import replace
from pathlib import Path

import pytest

from transume.controller import build_draft, build_image_action
from transume.domain import DeviceIdentity, JobOperation
from transume.images import SourceDisk, SourcePartition, SourceTopology, parse_clonezilla_image
from transume.model import DeviceItem
from transume.capabilities import ClonezillaCapabilities


def identity(path, kind="disk", serial="SERIAL", size=1000):
    return DeviceIdentity(path, f"/sys/class/block/{Path(path).name}", "8:0",
                          kind, size, serial=serial)


def item(path, kind="disk", serial="SERIAL", size=1000):
    return DeviceItem(Path(path).name, path, "1.0 GiB", True, True, "Available",
                      identity(path, kind, serial, size))


def test_backup_draft_uses_device_identity_and_repository(tmp_path):
    spec = build_draft("backup", {"source": item("/dev/sda"), "destination": tmp_path})
    assert spec.operation is JobOperation.SAVEDISK
    assert spec.sources[0].serial == "SERIAL"
    assert spec.repository == str(tmp_path)
    assert spec.options["compression"] == "zstd"
    assert dict(spec.options) == {"compression": "zstd", "engine": "partclone", "verify_image": True, "rescue": False,
                                  "filesystem_check": "check", "checksum": "none", "image_size": 0, "encrypt": False}


def test_backup_draft_merges_visible_options_and_uses_selected_image_name(tmp_path):
    spec = build_draft("backup", {"source": item("/dev/sda"), "destination": tmp_path,
                                  "image_name": "chosen-backup",
                                  "options": {"compression": "lz4", "verify_image": False, "rescue": True}})
    assert spec.image_name == "chosen-backup"
    assert dict(spec.options) == {"compression": "lz4", "engine": "partclone", "verify_image": False, "rescue": True,
                                  "filesystem_check": "check", "checksum": "none", "image_size": 0, "encrypt": False}


def test_backup_rejects_conflicting_or_invalid_image_name(tmp_path):
    (tmp_path / "taken").mkdir()
    with pytest.raises(ValueError, match="already exists"):
        build_draft("backup", {"source": item("/dev/sda"), "destination": tmp_path, "image_name": "taken"})
    with pytest.raises(ValueError, match="safe"):
        build_draft("backup", {"source": item("/dev/sda"), "destination": tmp_path, "image_name": "not safe"})


def test_encrypted_backup_requires_ecryptfs_when_capabilities_are_known(tmp_path):
    capabilities = ClonezillaCapabilities(None, frozenset({"ocs-sr", "partclone", "zstd"}),
                                          frozenset({"savedisk"}), frozenset({"zstd"}))
    with pytest.raises(ValueError, match="ecryptfs"):
        build_draft("backup", {"source": item("/dev/sda"), "destination": tmp_path,
                                "options": {"encrypt": True}, "capabilities": capabilities})


def test_encrypted_partition_backup_is_rejected_for_clonezilla_599(tmp_path):
    with pytest.raises(ValueError, match="encrypted partition backups"):
        build_draft("backup", {
            "source": item("/dev/sda1", "part"), "destination": tmp_path,
            "options": {"encrypt": True},
        })


def test_restore_draft_treats_image_as_image_not_device(tmp_path):
    image_path = tmp_path / "image-one"
    image_path.mkdir()
    (image_path / "parts").write_text("sda1\n")
    (image_path / "disk").write_text("sda\n")
    (image_path / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    image = parse_clonezilla_image(image_path)
    spec = build_draft("restore", {
        "source": image,
        "destination": item("/dev/sdb", serial="DEST"),
    })
    assert spec.operation is JobOperation.RESTOREDISK
    assert not spec.sources
    assert spec.repository == str(tmp_path)
    assert spec.image_name == "image-one"


def test_clone_requires_matching_device_types():
    with pytest.raises(ValueError):
        build_draft("clone", {
            "source": item("/dev/sda", "disk"),
            "destination": item("/dev/sdb1", "part", "DEST"),
        })


def test_clone_rejects_same_device():
    source = item("/dev/sda")
    with pytest.raises(ValueError, match="different devices"):
        build_draft("clone", {"source": source, "destination": source})


def test_clone_rejects_smaller_destination_even_with_resize():
    with pytest.raises(ValueError, match="smaller"):
        build_draft("clone", {
            "source": item("/dev/sda", size=2000),
            "destination": item("/dev/sdb", serial="DEST", size=1000),
            "options": {"resize": True},
        })


def test_restore_rejects_smaller_destination_even_with_resize(tmp_path):
    image_path = tmp_path / "image-one"
    image_path.mkdir()
    (image_path / "parts").write_text("sda1\n")
    (image_path / "disk").write_text("sda\n")
    (image_path / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    parsed = parse_clonezilla_image(image_path)
    image = replace(parsed, topology=SourceTopology((SourceDisk("sda", 2000),), (), 2000))
    with pytest.raises(ValueError, match="smaller"):
        build_draft("restore", {
            "source": image,
            "destination": item("/dev/sdb", serial="DEST", size=1000),
            "options": {"resize": True},
        })


def test_restore_partition_rejects_smaller_destination(tmp_path):
    image_path = tmp_path / "partition-image"
    image_path.mkdir()
    (image_path / "parts").write_text("sda1\n")
    (image_path / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    parsed = parse_clonezilla_image(image_path)
    partition = SourcePartition("sda1", "sda", "ext4", size=2000)
    image = replace(parsed, topology=SourceTopology((), (partition,), 2000))
    with pytest.raises(ValueError, match="smaller"):
        build_draft("restore", {
            "source": image,
            "destination": item("/dev/sdb1", "part", "DEST", size=1000),
        })


def test_clone_draft_carries_selected_options():
    spec = build_draft("clone", {
        "source": item("/dev/sda"),
        "destination": item("/dev/sdb", serial="DEST"),
        "options": {"resize": True, "rescue": False, "force_dd": True},
    })
    assert dict(spec.options) == {
        "resize": True, "rescue": False, "force_dd": True, "hidden_data": False, "direct_io": False,
    }


@pytest.mark.parametrize("operation, options", [
    ("backup", {"compression": "bad"}),
    ("restore", {"resize": "yes"}),
    ("clone", {"hidden_data": 1}),
])
def test_drafts_reject_invalid_options(tmp_path, operation, options):
    selection = {"source": item("/dev/sda"), "destination": tmp_path, "options": options}
    if operation == "clone":
        selection["destination"] = item("/dev/sdb", serial="DEST")
    with pytest.raises(ValueError):
        build_draft(operation, selection)


def test_restore_rejects_bad_status_and_topology(tmp_path):
    image_path = tmp_path / "image-one"
    image_path.mkdir()
    (image_path / "parts").write_text("sda1\n")
    (image_path / "disk").write_text("sda\n")
    (image_path / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    image = parse_clonezilla_image(image_path)
    with pytest.raises(ValueError, match="full-disk"):
        build_draft("restore", {"source": image, "destination": item("/dev/sdb1", "part", "DEST")})
    (image_path / "md5sum.txt").write_text("checksum")
    needs_check = parse_clonezilla_image(image_path)
    with pytest.raises(ValueError, match="requires verification"):
        build_draft("restore", {"source": needs_check, "destination": item("/dev/sdb", serial="DEST"),
                                "options": {"check_image": False}})


def test_restore_rejects_incomplete_image(tmp_path):
    image_path = tmp_path / "broken"
    image_path.mkdir()
    image = parse_clonezilla_image(image_path)
    with pytest.raises(ValueError, match="incomplete"):
        build_draft("restore", {"source": image, "destination": item("/dev/sdb", serial="DEST")})


def test_restore_accepts_ecryptfs_topology_and_rejects_unsupported_encryption(tmp_path):
    image_path = tmp_path / "encrypted"
    image_path.mkdir()
    (image_path / "ecryptfs.info").write_text('disk_of_img="sda"\nparts_of_img="sda1"\ndisks_size_all_of_img="_2147MB"\n')
    spec = build_draft("restore", {"source": parse_clonezilla_image(image_path),
                                    "destination": item("/dev/sdb", serial="DEST", size=3_000_000_000)})
    assert spec.options["encrypted"] is True
    with pytest.raises(ValueError, match="smaller"):
        build_draft("restore", {"source": parse_clonezilla_image(image_path),
                                "destination": item("/dev/sdb", serial="DEST", size=1_000)})
    broken = tmp_path / "gocryptfs"
    broken.mkdir()
    (broken / "gocryptfs.conf").write_bytes(b"opaque")
    with pytest.raises(ValueError, match="topology"):
        build_draft("restore", {"source": parse_clonezilla_image(broken), "destination": item("/dev/sdb", serial="DEST")})
    missing = parse_clonezilla_image(tmp_path / "does-not-exist")
    with pytest.raises(ValueError, match="unsupported"):
        build_draft("restore", {"source": missing, "destination": item("/dev/sdb", serial="DEST")})


def test_image_actions_build_immutable_specs(tmp_path):
    path = tmp_path / "image"
    path.mkdir()
    (path / "parts").write_text("sda1\n")
    (path / "disk").write_text("sda\n")
    (path / "sda1.ext4-ptcl-img").write_bytes(b"data")
    image = parse_clonezilla_image(path)
    check = build_image_action("check", image)
    assert check.operation is JobOperation.CHECK_IMAGE and check.risk == "read-only"


def test_typed_multidisk_draft_keeps_explicit_target_order(tmp_path):
    from transume.draft import JobDraft

    image_path = tmp_path / "two-disks"
    image_path.mkdir()
    (image_path / "parts").write_text("sda1\nsdb1\n")
    (image_path / "disk").write_text("sda\nsdb\n")
    (image_path / "sda1.ext4-ptcl-img").write_bytes(b"a")
    (image_path / "sdb1.ext4-ptcl-img").write_bytes(b"b")
    draft = JobDraft("restore")
    draft.set_source(parse_clonezilla_image(image_path))
    draft.set_destinations([
        item("/dev/sdc", serial="FIRST"),
        item("/dev/sdd", serial="SECOND"),
    ])

    spec = build_draft(draft)

    assert tuple(value.path for value in spec.destinations) == ("/dev/sdc", "/dev/sdd")


def test_restore_requires_exact_topology_cardinality(tmp_path):
    image_path = tmp_path / "image"; image_path.mkdir()
    (image_path / "parts").write_text("sda1\n")
    (image_path / "disk").write_text("sda\n")
    (image_path / "sda1.ext4-ptcl-img").write_bytes(b"data")
    destinations = (item("/dev/sdc", serial="EXTRA"), item("/dev/sdd", serial="EXTRA2"))
    with pytest.raises(ValueError, match="explicit destination mapping"):
        build_draft("restore", {"source": parse_clonezilla_image(image_path), "destinations": destinations,
                                "destination": None})


def test_single_partition_restore_uses_explicit_clonezilla_source(tmp_path):
    image_path = tmp_path / "one-part"; image_path.mkdir()
    (image_path / "parts").write_text("sda2\n")
    (image_path / "sda-pt.sf").write_text("/dev/sda2 : start=2048, size=4096\n")
    (image_path / "sda2.ext4-ptcl-img").write_bytes(b"data")

    spec = build_draft("restore", {
        "source": parse_clonezilla_image(image_path),
        "destination": item("/dev/sdb1", kind="part", serial="TARGET", size=4096 * 512),
    })

    assert spec.operation is JobOperation.RESTOREPARTS
    assert spec.options["source_partition"] == "sda2"


def test_multi_partition_restore_requires_corresponding_names(tmp_path):
    image_path = tmp_path / "parts"; image_path.mkdir()
    (image_path / "parts").write_text("sda1 sda2\n")
    (image_path / "sda-pt.sf").write_text(
        "/dev/sda1 : start=2048, size=4096\n/dev/sda2 : start=6144, size=4096\n"
    )
    (image_path / "sda1.ext4-ptcl-img").write_bytes(b"one")
    (image_path / "sda2.ext4-ptcl-img").write_bytes(b"two")
    image = parse_clonezilla_image(image_path)

    spec = build_draft("restore", {
        "source": image,
        "destinations": (
            item("/dev/sda1", kind="part", serial="ONE", size=4096 * 512),
            item("/dev/sda2", kind="part", serial="TWO", size=4096 * 512),
        ),
        "destination": None,
    })
    assert tuple(target.path for target in spec.destinations) == ("/dev/sda1", "/dev/sda2")
    assert "source_partition" not in spec.options

    with pytest.raises(ValueError, match="corresponding target partition names"):
        build_draft("restore", {
            "source": image,
            "destinations": (
                item("/dev/sdb1", kind="part", serial="ONE", size=4096 * 512),
                item("/dev/sdb2", kind="part", serial="TWO", size=4096 * 512),
            ),
            "destination": None,
        })
