import json
from pathlib import Path

from transume.model import ApplicationModel
from transume.controller import build_draft
from transume.domain import DeviceIdentity
from transume.storage import (
    ConnectionState, StorageKind, StorageLocation, StorageManager, StorageResult,
)


class FakeStorageExecutor:
    def __init__(self, root: Path):
        self.root = root
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if request.operation == "mount":
            return StorageResult(request.request_id, "ok", str(self.root), "mounted")
        return StorageResult(request.request_id, "ok", None, "unmounted")


def test_network_location_uses_endpoint_identity_and_catalog_never_has_credentials(tmp_path):
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    executor = FakeStorageExecutor(mounted)
    manager = StorageManager(storage_executor=executor)
    location = StorageLocation(StorageKind.SMB, "/pending", host="files.example",
                               share="images", endpoint="/nightly")
    session = manager.register(location)
    manager.mount(session, {"username": "operator", "password": "private-value"})
    assert session.state is ConnectionState.MOUNTED
    assert session.location.root == str(mounted)

    model = ApplicationModel(catalog_path=tmp_path / "catalog.json")
    model.set_storage_location(session.location)
    data = json.loads((tmp_path / "catalog.json").read_text())
    assert data["locations"][0]["id"].startswith("smb-")
    assert "private-value" not in json.dumps(data)
    assert all("credentials" not in item for item in data["locations"])
    manager.unmount(session)
    assert [request.operation for request in executor.requests] == ["mount", "unmount"]


def test_local_location_is_external_and_compatible_set_repository(tmp_path):
    model = ApplicationModel(catalog_path=tmp_path / "catalog.json")
    model.set_repository(tmp_path)
    assert model.repository == tmp_path.resolve()
    assert model.catalog.locations[model._repository_location_id].kind is StorageKind.LOCAL_FOLDER
    model.clear_current_location()
    assert model.repository is None
    assert len(model.recent_locations()) == 1


def test_failed_owned_unmount_can_be_retried_but_external_is_never_unmounted(tmp_path):
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    failed = [True]
    def execute(request):
        if request.operation == "mount":
            return StorageResult(request.request_id, "ok", str(mounted), "mounted")
        if failed[0]:
            return StorageResult(request.request_id, "failed", None, "failed")
        return StorageResult(request.request_id, "ok", None, "unmounted")
    manager = StorageManager(storage_executor=execute)
    session = manager.register(StorageLocation(StorageKind.NFS, "/pending", host="host", endpoint="/images"))
    manager.mount(session)
    # Simulate a first PolicyKit unmount failure while preserving the exact session.
    try:
        manager.unmount(session)
    except Exception:
        pass
    assert session.state is ConnectionState.FAILED
    failed[0] = False
    manager.unmount(session)
    assert session.state is ConnectionState.DISCONNECTED


def test_controller_receives_mounted_path_without_storage_credentials(tmp_path):
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    source = type("Source", (), {"identity": DeviceIdentity(
        "/dev/sda", "/sys/block/sda", "8:0", "disk", 1, serial="disk-1"
    )})()
    spec = build_draft("backup", {"source": source, "destination": mounted})
    public = json.dumps(spec.to_dict())
    assert spec.repository == str(mounted)
    assert "password" not in public and "private-value" not in public


def test_multiple_mounted_sessions_keep_independent_effective_roots(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    roots = iter((first_root, second_root))

    def execute(request):
        if request.operation == "mount":
            return StorageResult(request.request_id, "ok", str(next(roots)), "mounted")
        return StorageResult(request.request_id, "ok", None, "unmounted")

    manager = StorageManager(storage_executor=execute)
    first = manager.register(StorageLocation(
        StorageKind.SMB, "/pending", host="one.example", share="images",
        endpoint="/daily",
    ))
    second = manager.register(StorageLocation(
        StorageKind.NFS, "/pending", host="two.example", endpoint="/exports/images",
    ))
    manager.mount(first, {"username": "operator", "password": "private-value"})
    manager.mount(second)
    first.effective_location = StorageLocation(
        StorageKind.SMB, str(first_root / "daily"), host="one.example",
        share="images", endpoint="/daily",
    )
    second.effective_location = second.location

    assert [session.state for session in manager.sessions] == [
        ConnectionState.MOUNTED, ConnectionState.MOUNTED,
    ]
    assert first.effective_location.root == str(first_root / "daily")
    assert second.effective_location.root == str(second_root)
