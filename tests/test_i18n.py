import gettext
import subprocess
from pathlib import Path

from transume.i18n import DOMAIN, _select_locale_dir


ROOT = Path(__file__).resolve().parents[1]


def test_russian_catalog_is_compiled_and_loadable(tmp_path):
    localedir = tmp_path / "locale"
    catalog = localedir / "ru" / "LC_MESSAGES" / f"{DOMAIN}.mo"
    catalog.parent.mkdir(parents=True)
    subprocess.run(
        ["msgfmt", "--check", "--output-file", str(catalog), str(ROOT / "po/ru.po")],
        check=True,
    )
    translation = gettext.translation(DOMAIN, localedir=localedir, languages=["ru"])
    assert translation.gettext("Backup") == "Резервное копирование"


def test_installed_layout_does_not_use_glibc_locale_directory(tmp_path):
    source_root = tmp_path / "usr" / "lib"
    (source_root / "locale").mkdir(parents=True)
    installed_locale = tmp_path / "usr" / "share" / "locale"

    assert _select_locale_dir(source_root, installed_locale) == installed_locale
