from pathlib import Path

import pytest

from transume.images import ImageProblemCode, ImageStatus, ImageType, parse_clonezilla_image

FIXTURES = Path(__file__).parent / "fixtures" / "images"

def write_image(root: Path, files: dict[str, bytes | str]) -> Path:
    root.mkdir()
    for name, value in files.items():
        (root / name).write_bytes(value if isinstance(value, bytes) else value.encode())
    return root


@pytest.fixture
def ready_savedisk(tmp_path: Path) -> Path:
    return write_image(tmp_path / "savedisk", {"parts": "sda1\n", "disk": "sda\n", "sda1.ext4-ptcl-img": b"data"})


def test_ready_savedisk_has_topology_and_payload_size(ready_savedisk: Path):
    image = parse_clonezilla_image(ready_savedisk, location_id="usb")
    assert image.status is ImageStatus.READY
    assert image.image_type is ImageType.SAVEDISK
    assert image.source_disks == ("sda",)
    assert image.topology.disks[0].partitions[0].name == "sda1"
    assert image.payload_size == 4
    assert image.created_at is not None


def test_saveparts_inferrs_disk_from_parted_metadata(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "parts", {"parts": "nvme0n1p1\n", "nvme0n1-pt.parted": "", "nvme0n1p1.ext4-ptcl-img": b"x"}))
    assert image.status is ImageStatus.READY
    assert image.image_type is ImageType.SAVEPARTS
    assert image.source_disks == ("nvme0n1",)


def test_multiple_disks_are_preserved(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "multiple", {"parts": "sda1\nsdb1\n", "disk": "sda\nsdb\n", "sda1.ext4-ptcl-img": b"a", "sdb1.dd-img": b"b"}))
    assert image.status is ImageStatus.READY
    assert tuple(disk.name for disk in image.topology.disks) == ("sda", "sdb")


def test_space_delimited_multi_disk_metadata_is_preserved(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "space-delimited", {
        "parts": "sda1 sdb1\n", "disk": "sda sdb\n",
        "sda1.ext4-ptcl-img.zst": b"a", "sdb1.ext4-ptcl-img.zst": b"b",
    }))

    assert image.source_disks == ("sda", "sdb")
    assert image.source_partitions == ("sda1", "sdb1")
    assert tuple(part.disk for part in image.topology.partitions) == ("sda", "sdb")


def test_missing_parts_is_an_incomplete_representable_candidate(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "broken", {"disk": "sda\n", "sda1.ext4-ptcl-img": b"a"}))
    assert image.status is ImageStatus.INCOMPLETE
    assert ImageProblemCode.MISSING_PARTS in {problem.code for problem in image.problems}


def test_split_compressed_payload_and_checksum_need_verification(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "split", {"parts": "sda1\n", "disk": "sda\n", "sda1.ext4-ptcl-img.zst.aa": b"abc", "sda1.ext4-ptcl-img.zst.ab": b"de", "sha256sum.txt": ""}))
    assert image.status is ImageStatus.NEEDS_VERIFICATION
    assert image.payload_size == 5
    assert image.split
    assert image.compression == ("zstd",)


def test_symlinked_payload_is_rejected_without_following_it(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    root = write_image(tmp_path / "linked", {"parts": "sda1\n", "disk": "sda\n"})
    (root / "sda1.ext4-ptcl-img").symlink_to(outside)
    image = parse_clonezilla_image(root)
    assert image.status is ImageStatus.UNSUPPORTED
    assert image.payload_files == ()
    assert ImageProblemCode.SYMLINK_REJECTED in {problem.code for problem in image.problems}


def test_gocryptfs_marker_is_decryptable_even_without_plaintext_metadata(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "encrypted", {
        "gocryptfs.conf": b"opaque", "gocryptfs.diriv": b"opaque",
    }))
    assert image.status is ImageStatus.ENCRYPTED
    assert ImageProblemCode.ENCRYPTED_TOPOLOGY_UNAVAILABLE in {problem.code for problem in image.problems}


def test_ecryptfs_info_recovers_plaintext_encrypted_topology(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "encrypted", {
        "ecryptfs.info": 'disk_of_img="sda"\nparts_of_img="sda1"\ndisks_size_all_of_img="_2147MB"\n',
        "disk": b"opaque", "parts": b"opaque", "blkid.list": b"\xff",
        "blkdev.list": b"\xff", "sda-pt.parted": b"\xff", "Info-packages.txt": b"\xff",
    }))
    assert image.status is ImageStatus.ENCRYPTED
    assert image.image_type is ImageType.SAVEDISK
    assert image.source_disks == ("sda",) and image.source_partitions == ("sda1",)
    assert image.topology.disks[0].size == 2_147_000_000
    assert not any(problem.code is ImageProblemCode.ENCRYPTED_TOPOLOGY_UNAVAILABLE for problem in image.problems)
    assert image.metadata_warnings == ()
    assert image.clonezilla_version is None


def test_machine_parted_blkdev_and_info_metadata_are_preserved(tmp_path: Path):
    image = parse_clonezilla_image(FIXTURES / "nvme-metadata")
    disk = image.topology.disks[0]
    part = disk.partitions[0]
    assert (disk.size, disk.model, disk.serial, disk.partition_table) == (1000000, "Fast Disk", "SN-1", "gpt")
    assert (part.start, part.size, part.filesystem, part.label, part.partlabel, part.included) == (2048 * 512, 2048 * 512, "ext4", "root", "Linux root", True)
    assert image.logical_size == 1000000
    assert image.clonezilla_version == "3.1.2-9"


def test_missing_determinable_split_chunk_is_damaged(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "damaged", {
        "parts": "sda1\n", "disk": "sda\n", "sda1.ext4-ptcl-img.gz.aa": b"a", "sda1.ext4-ptcl-img.gz.ac": b"c",
    }))
    assert image.status is ImageStatus.DAMAGED
    assert image.split_parts == 2
    assert any(problem.path.endswith(".ab") for problem in image.problems)


def test_old_and_malformed_optional_metadata_remain_usable(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "old", {
        "parts": "sda1\n", "disk": "sda\n", "sda-pt.parted": "not a parted format\n", "sda1.partimage.000": b"x",
    }))
    assert image.status is ImageStatus.READY
    assert ImageProblemCode.MALFORMED_TOPOLOGY in {warning.code for warning in image.metadata_warnings}


def test_human_parted_metadata_provides_topology_without_warning(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "human-parted", {
        "parts": "sda1\n", "disk": "sda\n", "sda1.ext4-ptcl-img.xz": b"x",
        "sda-pt.parted": """Model: ATA Disk (scsi)
Disk /dev/sda: 4194304s
Sector size (logical/physical): 512B/512B
Partition Table: gpt

Number  Start  End       Size      File system  Name
 1      2048s  4192255s  4190208s  ext4         source
""",
    }))

    assert image.metadata_warnings == ()
    assert image.logical_size == 4_194_304 * 512
    assert image.topology.disks[0].partition_table == "gpt"
    assert (image.topology.partitions[0].start, image.topology.partitions[0].size) == (2048 * 512, 4_190_208 * 512)


def test_multi_disk_order_and_mmc_partition_mapping(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "ordered", {
        "parts": "mmcblk0p1\nsda1\n", "disk": "mmcblk0\nsda\n", "mmcblk0p1.ext4-ptcl-img": b"a", "sda1.dd-img": b"b",
    }))
    assert image.source_disks == ("mmcblk0", "sda")
    assert [part.disk for part in image.topology.partitions] == ["mmcblk0", "sda"]


def test_clonezilla_ntfs_img_and_lzo_payload_is_supported(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "ntfs-lzo", {
        "parts": "sda1\n", "disk": "sda\n", "sda1.ntfs-img.lzo.aa": b"data",
    }))

    assert image.status is ImageStatus.READY
    assert image.source_partitions == ("sda1",)
    assert image.payload_files == ("sda1.ntfs-img.lzo.aa",)
    assert image.compression == ("lzo",)


def test_legacy_lzma_compression_is_identified(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "lzma", {
        "parts": "sda1\n", "disk": "sda\n", "sda1.ext4-ptcl-img.lzma.aa": b"data",
    }))

    assert image.status is ImageStatus.READY
    assert image.compression == ("lzma",)


def test_each_parts_entry_requires_a_payload(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "partial", {
        "parts": "sda1 sda2\n", "disk": "sda\n", "sda1.ext4-ptcl-img.zst": b"data",
    }))

    assert image.status is ImageStatus.INCOMPLETE
    missing = [problem for problem in image.problems
               if problem.code is ImageProblemCode.MISSING_PAYLOAD]
    assert [(problem.message, problem.path) for problem in missing] == [
        ("Clonezilla partition payload is missing", "sda2"),
    ]


def test_clonezilla_lvm_metadata_preserves_multiple_pvs_and_lvs(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "lvm", {
        "parts": "sda1\n", "disk": "sda\n",
        "transume_test_vg-root.ext4-ptcl-img": b"root",
        "transume_test_vg-home.dd-ptcl-img": b"home",
        "lvm_vg_dev.list": (
            "vgtest /dev/sda1 i20UTQ-OaX3-c6nB-CiBv-Gav1-hgVf-tEkO2W\n"
            "vgtest /dev/sdb1 j30UTQ-OaX3-c6nB-CiBv-Gav1-hgVf-tEkO3X\n"
        ),
        "lvm_logv.list": (
            "/dev/vgtest/root  Linux rev 1.0 ext4 filesystem data\n"
            "/dev/vgtest/home  Linux rev 1.0 xfs filesystem data\n"
        ),
        "lvm_vgtest.conf": "contents = \"Text Format Volume Group\"\n",
    }))

    assert len(image.lvm.volume_groups) == 1
    assert [pv.device_node for pv in image.lvm.volume_groups[0].physical_volumes] == [
        "/dev/sda1", "/dev/sdb1",
    ]
    assert [(lv.vg_name, lv.name) for lv in image.lvm.logical_volumes] == [
        ("vgtest", "root"), ("vgtest", "home"),
    ]
    assert image.lvm.volume_groups[0].config_file == "lvm_vgtest.conf"


def test_malformed_lvm_metadata_fails_closed_without_hiding_image(tmp_path: Path):
    image = parse_clonezilla_image(write_image(tmp_path / "bad-lvm", {
        "parts": "sda1\n", "disk": "sda\n", "sda1.ext4-ptcl-img": b"data",
        "lvm_vg_dev.list": "vgtest /dev/sda1 not-an-lvm-uuid\n",
        "lvm_logv.list": "/dev/vgtest/root  ext4 filesystem data\n",
        "lvm_vgtest.conf": "config\n",
    }))

    assert image.status is ImageStatus.READY
    assert not image.lvm.volume_groups and not image.lvm.logical_volumes
    assert ImageProblemCode.UNSUPPORTED_METADATA in {
        warning.code for warning in image.metadata_warnings
    }
