import pytest

from transume.ui.gtk import set_accessible_label, set_accessible_role
from transume.ui.pages import _call_model, _smb_credentials
from transume.i18n import _


class TooltipWidget:
    def __init__(self):
        self.tooltip = None

    def set_tooltip_text(self, text):
        self.tooltip = text


def test_accessibility_helpers_tolerate_old_gtk_widgets():
    widget = TooltipWidget()
    set_accessible_label(widget, "Choose source")
    set_accessible_role(widget, object())
    assert widget.tooltip == "Choose source"


def test_call_model_returns_presentable_error_instead_of_hiding_it():
    class Broken:
        def list_images(self):
            raise RuntimeError("catalog unavailable")

    values, error = _call_model(Broken(), "list_images")
    assert values == []
    assert error == _("Could not load {method}: {error}").format(
        method="list images", error="catalog unavailable"
    )


def test_smb_credentials_require_complete_named_login():
    assert _smb_credentials("", "", "") == {}
    assert _smb_credentials("WG", "Administrator", "secret") == {
        "domain": "WG", "username": "Administrator", "password": "secret",
    }
    with pytest.raises(ValueError, match="SMB password is required"):
        _smb_credentials("WG", "Administrator", "")
    with pytest.raises(ValueError, match="SMB username is required"):
        _smb_credentials("WG", "", "secret")
