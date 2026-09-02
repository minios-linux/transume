import os
from types import SimpleNamespace

import pytest

import transume.runner as runner
from transume.runner import RunnerValidationError, caller_identity


def test_caller_identity_requires_strict_pkexec_uid(monkeypatch):
    for value in (None, "", " 1000", "+1000", "01000", "root", "0"):
        if value is None:
            monkeypatch.delenv("PKEXEC_UID", raising=False)
        else:
            monkeypatch.setenv("PKEXEC_UID", value)
        with pytest.raises(RunnerValidationError):
            caller_identity()


def test_caller_identity_uses_pkexec_uid_not_client_input(monkeypatch):
    monkeypatch.setenv("PKEXEC_UID", "1000")
    monkeypatch.setattr(
        runner.pwd, "getpwuid",
        lambda uid: SimpleNamespace(pw_uid=uid, pw_gid=1000),
    )
    assert caller_identity() == (1000, 1000)


def test_dry_run_allows_an_injected_existing_desktop_uid(monkeypatch):
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    monkeypatch.setattr(
        runner.pwd, "getpwuid",
        lambda uid: SimpleNamespace(pw_uid=uid, pw_gid=1000),
    )
    assert caller_identity(caller_uid=1000, dry_run=True) == (1000, 1000)
