import json
import subprocess

from transume.inventory import scan_block_devices
from transume.model import ApplicationModel, format_size


def test_format_size():
    assert format_size(1024) == "1.0 KiB"
    assert format_size(1024 ** 3) == "1.0 GiB"


def test_image_discovery(tmp_path):
    complete = tmp_path / "workstation"
    complete.mkdir()
    (complete / "parts").write_text("sda1", encoding="utf-8")
    (complete / "clonezilla-img").write_text("log", encoding="utf-8")
    incomplete = tmp_path / "partial"
    incomplete.mkdir()
    (incomplete / "parts").write_text("sdb1", encoding="utf-8")
    (tmp_path / "ordinary").mkdir()

    (complete / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    (complete / "disk").write_text("sda\n", encoding="utf-8")
    (incomplete / "disk").write_text("sda\n", encoding="utf-8")
    model = ApplicationModel(catalog_path=tmp_path / "catalog.json")
    model.set_repository(tmp_path)
    images = {image.name: image for image in model.list_images()}
    assert set(images) == {"partial", "workstation"}
    assert images["workstation"].status.value == "ready"
    assert images["partial"].status.value == "incomplete"


def test_scan_block_devices_invokes_machine_readable_lsblk(monkeypatch):
    payload = json.dumps({"blockdevices": [{"name": "sdb", "path": "/dev/sdb",
                                             "type": "disk", "size": 100}]})
    called = {}

    def fake_run(command, **kwargs):
        called["command"] = command
        called["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, payload, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    devices = scan_block_devices()
    assert devices[0].path == "/dev/sdb"
    assert "--json" in called["command"] and "--bytes" in called["command"]
    assert called["kwargs"].get("shell", False) is False


def test_application_model_hides_technical_devices(monkeypatch):
    payload = json.dumps({"blockdevices": [
        {"name": "loop0", "type": "loop", "size": 1},
        {"name": "zram0", "path": "/dev/zram0", "type": "disk", "size": 1},
        {"name": "sda", "path": "/dev/sda", "type": "disk", "size": 100,
         "model": "Test Disk", "serial": "SERIAL", "maj:min": "8:0"},
    ]})
    devices = __import__("transume.inventory", fromlist=["parse_lsblk_json"]).parse_lsblk_json(payload)
    monkeypatch.setattr("transume.model.scan_block_devices", lambda: devices)
    monkeypatch.setattr("transume.model.ApplicationModel._identity_or_none", lambda _self, _item: object())
    items = ApplicationModel().list_devices()
    assert [item.name for item in items] == ["Test Disk"]


def test_application_model_returns_disks_without_stable_identity(monkeypatch):
    payload = json.dumps({"blockdevices": [{
        "name": "sda", "path": "/dev/sda", "type": "disk", "size": 100,
        "model": "Anonymous Disk", "maj:min": "8:0",
    }]})
    devices = __import__(
        "transume.inventory", fromlist=["parse_lsblk_json"]
    ).parse_lsblk_json(payload)
    monkeypatch.setattr("transume.model.scan_block_devices", lambda: devices)
    monkeypatch.setattr(
        "transume.model.ApplicationModel._identity_or_none",
        lambda _self, _item: None,
    )
    item = ApplicationModel().list_devices()[0]
    assert item.name == "Anonymous Disk"
    assert item.status == "No stable identity"
    assert not item.selectable_source


def test_network_interfaces_are_discovered_from_sysfs(monkeypatch, tmp_path):
    net = tmp_path / "net"
    for name, mac, state in (("lo", "00:00:00:00:00:00", "unknown"), ("eth0", "02:00:00:00:00:01", "up")):
        entry = net / name
        entry.mkdir(parents=True)
        (entry / "address").write_text(mac)
        (entry / "operstate").write_text(state)
    model = ApplicationModel()
    real_path = __import__("pathlib").Path
    monkeypatch.setattr("transume.model.Path", lambda value: net if value == "/sys/class/net" else real_path(value))
    interfaces = model.list_network_interfaces()
    assert [(item.name, item.mac, item.state) for item in interfaces] == [("eth0", "02:00:00:00:00:01", "up")]


def test_activity_history_restarts_is_bounded_and_redacted(tmp_path):
    path = tmp_path / "activity.json"
    model = ApplicationModel(catalog_path=tmp_path / "catalog.json", activity_path=path)
    class Device:
        path = "/dev/sda"
        serial = "SECRET-SERIAL"
        wwn = "SECRET-WWN"
    class Spec:
        sources = (Device(),)
        destinations = (Device(),)
    for number in range(101):
        job_id = model.start_activity(f"copy {number}", Spec())
        model.finish_activity(job_id, "failed", "password=topsecret ocs-sr --full-command")
    records = list(ApplicationModel(catalog_path=tmp_path / "catalog.json", activity_path=path).list_activity())
    assert len(records) == 100
    assert records[0].operation == "copy 1"
    assert records[-1].source_label == "sda"
    assert records[-1].detail == "Operation failed"
    assert "SECRET" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600


def test_corrupt_activity_history_is_quarantined(tmp_path):
    path = tmp_path / "activity.json"
    path.write_text("not json")
    model = ApplicationModel(catalog_path=tmp_path / "catalog.json", activity_path=path)
    assert list(model.list_activity()) == []
    assert list(tmp_path.glob("activity.json.corrupt-*"))


def test_unsupported_activity_history_version_is_quarantined(tmp_path):
    path = tmp_path / "activity.json"
    path.write_text(json.dumps({"version": 999, "records": []}))
    model = ApplicationModel(catalog_path=tmp_path / "catalog.json", activity_path=path)
    assert list(model.list_activity()) == []
    assert list(tmp_path.glob("activity.json.corrupt-*"))


def test_activity_v1_migrates_and_orphan_logs_are_removed(tmp_path):
    path = tmp_path / "activity.json"
    legacy = {"job_id": "old", "operation": "copy", "started_at": "2026-01-01T00:00:00+00:00",
              "finished_at": None, "status": None, "source_label": "sda", "destination_label": "sdb",
              "detail": "Operation started", "progress_summary": None, "log_summary": None}
    path.write_text(json.dumps({"version": 1, "records": [legacy]}))
    logs = tmp_path / "logs"
    logs.mkdir()
    orphan = logs / "orphan.log"
    orphan.write_text("old")
    model = ApplicationModel(catalog_path=tmp_path / "catalog.json", activity_path=path)
    record = next(iter(model.list_activity()))
    assert record.exit_code is None and record.log_path is None
    assert not orphan.exists()


def test_activity_retention_deletes_owned_old_log(tmp_path):
    model = ApplicationModel(catalog_path=tmp_path / "catalog.json", activity_path=tmp_path / "activity.json")
    class Spec:
        sources = destinations = ()
    first = model.start_activity("copy", Spec())
    log = model.log_dir / f"{first}.log"
    log.parent.mkdir(mode=0o700)
    log.write_text("safe")
    for _ in range(100):
        model.start_activity("copy", Spec())
    assert not log.exists()
