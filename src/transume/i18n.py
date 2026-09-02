"""Translation helpers for Transume's user interface."""

from __future__ import annotations

import gettext
from pathlib import Path


DOMAIN = "transume"
SOURCE_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_LOCALE_DIR = SOURCE_ROOT / "locale"
INSTALLED_LOCALE_DIR = Path("/usr/share/locale")


def _select_locale_dir(source_root=SOURCE_ROOT, installed_locale_dir=INSTALLED_LOCALE_DIR):
    """Use repository catalogs only when running from the source tree."""
    source_root = Path(source_root)
    if (source_root / "pyproject.toml").is_file():
        return source_root / "locale"
    return Path(installed_locale_dir)


LOCALE_DIR = _select_locale_dir()

_translation = gettext.translation(DOMAIN, localedir=LOCALE_DIR, fallback=True)
_ = _translation.gettext
ngettext = _translation.ngettext
