from pathlib import Path

import pytest

from transume.filesystem import NoReplaceUnavailable, rename_noreplace


def test_rename_noreplace_never_overwrites_existing_target(tmp_path: Path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir(); target.mkdir()
    try:
        with pytest.raises(FileExistsError):
            rename_noreplace(source, target)
    except NoReplaceUnavailable:
        pytest.skip("kernel does not provide renameat2")
    assert source.is_dir() and target.is_dir()
