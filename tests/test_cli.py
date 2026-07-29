import json
import os

import pytest

from transume import cli
from transume.capabilities import ClonezillaCapabilities
from transume.client import ClientResult
from transume.domain import DeviceIdentity
from transume.inventory import BlockDevice


def identity(path="/dev/sdb"):
    return DeviceIdentity(path, "/sys/devices/test", "8:16", "disk", 1024, serial="SERIAL")


def device(value=None):
    value = value or identity()
    return BlockDevice("sdb", value.path, "disk", 1024, (), False, False, None, (), False,
                       False, False, False, True, True, value.major_minor, value.serial,
                       value.wwn)


class CurrentDevice:
    def __init__(self, value):
        self._value = value

    def identity(self):
        return self._value


def check_spec(repository):
    return {"job_id": "check", "operation": "check-image", "sources": [], "destinations": [],
            "repository": str(repository), "image_name": "image",
            "image_fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "options": {},
            "required_capabilities": [], "risk": "read-only", "post_action": "none"}


def available():
    return ClonezillaCapabilities("1", frozenset({"ocs-chkimg"}), frozenset({"check-image"}), frozenset())


def test_selector_requires_exactly_one_current_device():
    with pytest.raises(cli.CliError, match="exactly one"):
        cli._selector_identity({"serial": "SERIAL"}, (CurrentDevice(identity()), CurrentDevice(identity())))


def test_selector_rejects_path_only_selector():
    with pytest.raises(cli.CliError, match="exactly one of"):
        cli._selector_identity({"path": "/dev/sdb"}, (CurrentDevice(identity()),))


def test_by_id_selector_is_accepted():
    value = DeviceIdentity("/dev/sdb", "/sys/devices/test", "8:16", "disk", 1024,
                           by_id=("/dev/disk/by-id/wwn-test",))
    assert cli._selector_identity({"by_id": "/dev/disk/by-id/wwn-test"}, (CurrentDevice(value),)) == value


def test_strict_schema_rejects_unknown_field(tmp_path):
    value = check_spec(tmp_path)
    value["unexpected"] = True
    with pytest.raises(cli.CliError, match="invalid PublicJobSpec"):
        cli._parse_spec(value)


def test_secret_keys_are_rejected(tmp_path):
    path = tmp_path / "job.json"
    path.write_text(json.dumps({"password": "no"}))
    with pytest.raises(cli.CliError, match="secrets"):
        cli._load_json(str(path))


def test_safe_reader_rejects_symlink_and_oversize(tmp_path):
    target = tmp_path / "target"
    target.write_text("{}")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(cli.CliError, match="non-symlink"):
        cli._read_input(str(link))
    large = tmp_path / "large"
    large.write_bytes(b"x" * (cli.MAX_INPUT_BYTES + 1))
    with pytest.raises(cli.CliError, match="exceeds"):
        cli._read_input(str(large))


def test_execute_requires_yes(tmp_path, monkeypatch, capsys):
    (tmp_path / "image").mkdir()
    source = tmp_path / "job.json"
    source.write_text(json.dumps(check_spec(tmp_path)))
    monkeypatch.setattr(cli, "probe_clonezilla", available)
    assert cli.main(["execute", str(source)]) == cli.EXIT_REFUSED
    assert capsys.readouterr().out == ""


def test_dry_run_json_is_redacted(tmp_path, monkeypatch, capsys):
    (tmp_path / "image").mkdir()
    source = tmp_path / "job.json"
    source.write_text(json.dumps(check_spec(tmp_path)))
    monkeypatch.setattr(cli, "probe_clonezilla", available)
    result = ClientResult("dry-run", "ok", ({"type": "log", "token": "private"},))
    assert cli.main(["dry-run", str(source)], runner=lambda *_args, **_kwargs: result) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "dry-run"
    assert output["events"][0]["token"] == "***"


def test_execute_with_yes_uses_normal_runner_mode(tmp_path, monkeypatch, capsys):
    (tmp_path / "image").mkdir()
    source = tmp_path / "job.json"
    source.write_text(json.dumps(check_spec(tmp_path)))
    monkeypatch.setattr(cli, "probe_clonezilla", available)
    calls = []
    assert cli.main(["execute", str(source), "--yes"],
                    runner=lambda _spec, *, dry_run: (calls.append(dry_run) or ClientResult("ok", "done"))) == 0
    assert calls == [False]
    assert json.loads(capsys.readouterr().out)["status"] == "ok"


def test_execute_refuses_encrypted_backup_in_structured_cli_path(tmp_path, monkeypatch, capsys):
    (tmp_path / "image").mkdir()
    source = tmp_path / "job.json"
    value = check_spec(tmp_path)
    value.update({"operation": "savedisk", "sources": [identity().to_dict()], "image_name": "backup",
                  "image_fingerprint": None, "options": {"encrypt": True}, "risk": "write-image"})
    source.write_text(json.dumps(value))
    monkeypatch.setattr(cli, "probe_clonezilla", lambda: ClonezillaCapabilities("1", frozenset({"ocs-sr"}), frozenset({"savedisk"}), frozenset()))
    monkeypatch.setattr(cli, "_validate_identities", lambda *_args: None)
    assert cli.main(["execute", str(source), "--yes"]) == cli.EXIT_VALIDATION
    assert "interactive UI secret channel" in capsys.readouterr().err


def test_validate_rejects_missing_command_binary(tmp_path):
    (tmp_path / "image").mkdir()
    spec = cli._parse_spec(check_spec(tmp_path))
    with pytest.raises(cli.CliError, match="ocs-chkimg"):
        cli.validate_spec(spec, capabilities=ClonezillaCapabilities("1", frozenset(), frozenset(), frozenset()))


def test_export_is_private_atomic_json(tmp_path):
    source = tmp_path / "job.json"
    source.write_text(json.dumps(check_spec(tmp_path)))
    destination = tmp_path / "export.json"
    assert cli.main(["export", str(source), "--output", str(destination)]) == 0
    assert stat_mode(destination) == 0o600
    assert json.loads(destination.read_text())["operation"] == "check-image"


def stat_mode(path):
    return os.stat(path).st_mode & 0o777
