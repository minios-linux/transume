"""Translation helpers for Transume's user interface."""

from __future__ import annotations

import gettext
from pathlib import Path


DOMAIN = "transume"
REPOSITORY_LOCALE_DIR = Path(__file__).resolve().parents[2] / "locale"
INSTALLED_LOCALE_DIR = Path("/usr/share/locale")
LOCALE_DIR = (
    REPOSITORY_LOCALE_DIR
    if REPOSITORY_LOCALE_DIR.is_dir()
    else INSTALLED_LOCALE_DIR
)

_translation = gettext.translation(DOMAIN, localedir=LOCALE_DIR, fallback=True)
_ = _translation.gettext
ngettext = _translation.ngettext
