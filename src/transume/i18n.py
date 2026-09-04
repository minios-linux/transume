"""Translation helpers for Transume's user interface."""

from __future__ import annotations

import gettext
import struct
from pathlib import Path


DOMAIN = "transume"
SOURCE_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_LOCALE_DIR = SOURCE_ROOT / "locale"
INSTALLED_LOCALE_DIR = Path("/usr/share/locale")


def _catalog_is_current(source_catalog, compiled_catalog):
    try:
        if compiled_catalog.stat().st_mtime < source_catalog.stat().st_mtime:
            return False
        with compiled_catalog.open("rb") as stream:
            gettext.GNUTranslations(stream)
    except (EOFError, IndexError, OSError, ValueError, struct.error):
        return False
    return True


def _select_locale_dir(source_root=SOURCE_ROOT, installed_locale_dir=INSTALLED_LOCALE_DIR):
    """Use repository catalogs only when running from the source tree."""
    source_root = Path(source_root)
    repository_locale_dir = source_root / "locale"
    source_catalogs = tuple((source_root / "po").glob("*.po"))
    catalogs_are_complete = source_catalogs and all(
        _catalog_is_current(
            catalog,
            repository_locale_dir / catalog.stem / "LC_MESSAGES" / f"{DOMAIN}.mo",
        )
        for catalog in source_catalogs
    )
    if (source_root / "pyproject.toml").is_file() and catalogs_are_complete:
        return repository_locale_dir
    return Path(installed_locale_dir)


LOCALE_DIR = _select_locale_dir()

_translation = gettext.translation(DOMAIN, localedir=LOCALE_DIR, fallback=True)
_ = _translation.gettext
ngettext = _translation.ngettext
