from pathlib import Path

import pytest

from transume.filesystem import NoReplaceUnavailable
from transume.domain import JobOperation, PublicJobSpec
from transume.model import ApplicationModel, ImageMutationError


def make_image(root: Path, name: str = "one") -> Path:
    path = root / name
    path.mkdir()
    (path / "parts").write_text("sda1\n")
    (path / "disk").write_text("sda\n")
    (path / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    return path


def model(tmp_path: Path) -> ApplicationModel:
    subject = ApplicationModel(catalog_path=tmp_path / "catalog.json", activity_path=tmp_path / "activity.json")
    subject.set_repository(tmp_path / "images")
    return subject


def test_rename_rejects_existing_target_without_overwrite(tmp_path: Path):
    root = tmp_path / "images"; root.mkdir()
    make_image(root, "one"); existing = make_image(root, "two")
    subject = model(tmp_path)
    candidate = subject.list_images()[0]
    with pytest.raises(ImageMutationError, match="already exists"):
        subject.rename_image(candidate, "two")
    assert existing.is_dir() and (root / "one").is_dir()


def test_rename_fails_closed_when_no_replace_is_unavailable(tmp_path: Path, monkeypatch):
    root = tmp_path / "images"; root.mkdir(); make_image(root)
    subject = model(tmp_path); candidate = subject.list_images()[0]
    monkeypatch.setattr("transume.model.rename_noreplace", lambda *_: (_ for _ in ()).throw(NoReplaceUnavailable("no syscall")))
    with pytest.raises(ImageMutationError, match="not renamed"):
        subject.rename_image(candidate, "new")
    assert (root / "one").is_dir() and not (root / "new").exists()


def test_mutations_reject_symlink_candidate_and_unsafe_trash(tmp_path: Path):
    root = tmp_path / "images"; root.mkdir(); outside = make_image(tmp_path, "outside")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    subject = model(tmp_path)
    from transume.images import parse_clonezilla_image
    linked = parse_clonezilla_image(root / "linked")
    with pytest.raises(ImageMutationError):
        subject.rename_image(linked, "new")
    make_image(root, "one"); candidate = subject.list_images()[0]
    (root / ".transume-trash").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ImageMutationError, match="Trash directory"):
        subject.delete_image(candidate, "one")


def test_delete_quarantines_then_removes_tree_without_following_symlink(tmp_path: Path):
    root = tmp_path / "images"; root.mkdir(); image = make_image(root)
    outside = tmp_path / "outside"; outside.write_text("keep")
    (image / "outside-link").symlink_to(outside)
    subject = model(tmp_path); candidate = subject.list_images()[0]
    subject.delete_image(candidate, "one")
    assert not image.exists()
    assert outside.read_text() == "keep"
    assert not list((root / ".transume-trash").iterdir())


def test_delete_failure_keeps_quarantined_recovery_path(tmp_path: Path, monkeypatch):
    root = tmp_path / "images"; root.mkdir(); make_image(root)
    subject = model(tmp_path); candidate = subject.list_images()[0]
    monkeypatch.setattr("transume.model._delete_quarantined_tree", lambda _path: (_ for _ in ()).throw(OSError("disk error")))
    with pytest.raises(ImageMutationError, match="quarantined") as error:
        subject.delete_image(candidate, "one")
    assert error.value.recovery_path is not None and error.value.recovery_path.is_dir()
    assert not (root / "one").exists()


def test_mutations_are_blocked_while_an_image_job_uses_the_location(tmp_path: Path):
    root = tmp_path / "images"; root.mkdir(); make_image(root)
    subject = model(tmp_path); candidate = subject.list_images()[0]
    job = PublicJobSpec("checking", JobOperation.CHECK_IMAGE, repository=str(root),
                        image_name="one", risk="read-only")
    job_id = subject.start_activity("check", job)
    with pytest.raises(ImageMutationError, match="in use"):
        subject.rename_image(candidate, "new")
    subject.finish_activity(job_id, "ok", "done")
