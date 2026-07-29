import os

import pytest

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
    monkeypatch.setenv("PKEXEC_UID", str(os.getuid()))
    assert caller_identity() == (os.getuid(), os.getgid())


def test_dry_run_allows_an_injected_existing_desktop_uid(monkeypatch):
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    assert caller_identity(caller_uid=os.getuid(), dry_run=True) == (os.getuid(), os.getgid())
