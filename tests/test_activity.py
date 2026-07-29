import stat

import pytest

from transume import activity
from transume.activity import LogStore
from transume.progress import elapsed_and_eta


def test_log_store_permissions_redaction_and_bounds(tmp_path):
    store = LogStore("job-1", root=tmp_path / "logs")
    store.append({"kind": "log", "message": "token=private https://host/?password=hunter2"})
    store.append({"kind": "log", "message": "x" * 9000})
    store.close()
    text = store.path.read_text()
    assert "private" not in text and "hunter2" not in text
    assert "[line truncated]" in text
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700


def test_log_store_rejects_symlink(tmp_path):
    root = tmp_path / "logs"
    root.mkdir(mode=0o700)
    (root / "job-1.log").symlink_to(tmp_path / "outside")
    with pytest.raises((OSError, ValueError)):
        LogStore("job-1", root=root)


def test_log_store_marks_total_size_truncation(tmp_path, monkeypatch):
    monkeypatch.setattr(activity, "MAX_SIZE", 100)
    store = LogStore("job-1", root=tmp_path / "logs")
    store.append({"kind": "log", "message": "x" * 90})
    store.close()
    assert "size limit reached" in store.path.read_text()
    assert store.path.stat().st_size <= 100


def test_elapsed_and_eta_requires_increasing_samples():
    elapsed, eta = elapsed_and_eta([(10.0, 10.0), (20.0, 60.0)], 25.0)
    assert elapsed == 15.0 and eta == 8.0
    assert elapsed_and_eta([(10.0, 10.0), (20.0, 10.0)], 25.0)[1] is None
