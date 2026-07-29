from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

from transume.catalog import Availability, CatalogLocation, ImageCatalog
import json
from transume.images import ImageProblemCode, ImageStatus
from transume.storage import StorageKind, StorageLocation


def image(path: Path, *, parts: bool = True) -> Path:
    path.mkdir(parents=True)
    if parts:
        (path / "parts").write_text("sda1\n")
    (path / "disk").write_text("sda\n")
    (path / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    return path


def catalog(tmp_path: Path, root: Path) -> ImageCatalog:
    return ImageCatalog(tmp_path / "catalog.json", [CatalogLocation("usb", StorageLocation(StorageKind.LOCAL_FOLDER, str(root)))])


def test_scans_selected_image_root(tmp_path: Path):
    root = image(tmp_path / "image")
    result = catalog(tmp_path, root).scan("usb")
    assert [item.name for item in result.candidates] == ["image"]


def test_scans_direct_children_by_default(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    image(root / "one")
    image(root / "nested" / "two")
    assert [item.name for item in catalog(tmp_path, root).scan("usb").candidates] == ["one"]


def test_ordinary_and_unreadable_directories_are_not_images(tmp_path: Path, monkeypatch):
    root = tmp_path / "images"
    root.mkdir()
    ordinary = root / "documents"
    ordinary.mkdir()
    unreadable = root / "lost+found"
    unreadable.mkdir()
    original_iterdir = Path.iterdir

    def iterdir(path: Path):
        if path == unreadable:
            raise PermissionError("not accessible")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    assert catalog(tmp_path, root).scan("usb").candidates == ()


def test_bounded_recursive_scan(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    image(root / "a" / "one")
    image(root / "a" / "b" / "two")
    assert [item.name for item in catalog(tmp_path, root).scan("usb", recursive_depth=1).candidates] == ["one"]
    assert {item.name for item in catalog(tmp_path, root).scan("usb", recursive_depth=2).candidates} == {"one", "two"}


def test_cancelled_scan_is_partial(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    image(root / "one")
    cancelled = Event()
    cancelled.set()
    result = catalog(tmp_path, root).scan("usb", cancel_event=cancelled)
    assert result.partial
    assert not result.candidates


def test_symlink_directories_are_rejected(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    outside = image(tmp_path / "outside")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    result = catalog(tmp_path, root).scan("usb")
    assert not result.candidates
    assert ImageProblemCode.SYMLINK_REJECTED in {item.code for item in result.problems}


def test_persistence_is_private_and_reloads(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    one = image(root / "one")
    (one / "lvm_vg_dev.list").write_text(
        "vgtest /dev/sda1 i20UTQ-OaX3-c6nB-CiBv-Gav1-hgVf-tEkO2W\n"
    )
    (one / "lvm_logv.list").write_text(
        "/dev/vgtest/root  Linux rev 1.0 ext4 filesystem data\n"
    )
    (one / "lvm_vgtest.conf").write_text("contents = \"Text Format Volume Group\"\n")
    first = catalog(tmp_path, root)
    first.refresh("usb")
    assert (tmp_path / "catalog.json").stat().st_mode & 0o777 == 0o600
    reloaded = ImageCatalog(tmp_path / "catalog.json")
    assert reloaded.entries[0].candidate.name == "one"
    assert reloaded.entries[0].candidate.lvm.logical_volumes[0].name == "root"
    assert reloaded.locations["usb"].root == str(root)


def test_ssh_location_persists_username_but_migrates_v1_without_it(tmp_path: Path):
    path = tmp_path / "catalog.json"
    old = {"schema_version": 1, "locations": [{"id": "nfs", "kind": "nfs", "root": "/mnt",
           "host": "files.example", "endpoint": "/exports", "share": None, "device": None, "port": None}], "entries": []}
    path.write_text(json.dumps(old))
    subject = ImageCatalog(path)
    subject.add_location("ssh", StorageLocation(StorageKind.SSH, "/pending", host="files.example",
                         endpoint="/images", username="operator", port=2222))
    data = json.loads(path.read_text())
    assert data["schema_version"] == 4
    assert data["locations"][1]["username"] == "operator"
    assert "password" not in json.dumps(data)


def test_malformed_image_like_folder_is_visible(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    broken = root / "broken"
    broken.mkdir()
    (broken / "disk").write_text("sda\n")
    result = catalog(tmp_path, root).scan("usb")
    assert result.candidates[0].status is ImageStatus.INCOMPLETE
    assert ImageProblemCode.MISSING_PARTS in {item.code for item in result.candidates[0].problems}


def test_refresh_isolated_by_location_and_retains_unavailable_history(tmp_path: Path):
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    image(one / "image")
    image(two / "image")
    subject = catalog(tmp_path, one)
    subject.add_location("other", StorageLocation(StorageKind.LOCAL_FOLDER, str(two)), persist=False)
    subject.refresh("usb")
    subject.refresh("other")
    for path in (one / "image").iterdir():
        path.unlink()
    (one / "image").rmdir()
    subject.refresh("usb")
    assert {(entry.candidate.location_id, entry.availability) for entry in subject.entries} == {("usb", Availability.UNAVAILABLE), ("other", Availability.AVAILABLE)}


def test_async_scan_uses_injected_executor_and_callback(tmp_path: Path):
    root = image(tmp_path / "image")
    called = []
    with ThreadPoolExecutor(max_workers=1) as executor:
        result = ImageCatalog(tmp_path / "catalog.json", [CatalogLocation("usb", StorageLocation(StorageKind.LOCAL_FOLDER, str(root)))], executor=executor).scan_async("usb", callback=called.append).result()
    assert called == [result]


def test_successful_verification_persists_for_unchanged_payload(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    image(root / "one")
    subject = catalog(tmp_path, root)
    candidate = subject.refresh("usb").candidates[0]
    subject.mark_verified(candidate)
    reloaded = ImageCatalog(tmp_path / "catalog.json")
    refreshed = reloaded.refresh("usb", root).candidates[0]
    assert refreshed.verification_current
    assert refreshed.verified_at is not None


def test_payload_mutation_invalidates_verification(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    payload = image(root / "one") / "sda1.ext4-ptcl-img"
    subject = catalog(tmp_path, root)
    subject.mark_verified(subject.refresh("usb").candidates[0])
    payload.write_bytes(b"changed payload")
    refreshed = subject.refresh("usb").candidates[0]
    assert not refreshed.verification_current
    assert refreshed.verified_at is None


def test_unverified_image_is_not_marked_by_failed_check(tmp_path: Path):
    root = tmp_path / "images"
    root.mkdir()
    subject = catalog(tmp_path, root)
    image(root / "one")
    candidate = subject.refresh("usb").candidates[0]
    # A failed/cancelled check does not call mark_verified; discovery alone is inert.
    assert candidate.verified_at is None
    assert not candidate.verification_current
