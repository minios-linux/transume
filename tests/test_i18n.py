import gettext
import os
import shutil
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


def test_source_layout_uses_compiled_repository_catalogs(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "po").mkdir()
    source_catalog = tmp_path / "po" / "ru.po"
    shutil.copy2(ROOT / "po" / "ru.po", source_catalog)
    repository_locale = tmp_path / "locale" / "ru" / "LC_MESSAGES"
    repository_locale.mkdir(parents=True)
    subprocess.run([
        "msgfmt", "--check", "--output-file",
        str(repository_locale / f"{DOMAIN}.mo"), str(source_catalog),
    ], check=True)

    assert _select_locale_dir(tmp_path, "/usr/share/locale") == tmp_path / "locale"


def test_source_layout_falls_back_until_catalogs_are_compiled(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "po").mkdir()
    (tmp_path / "po" / "ru.po").touch()
    installed_locale = tmp_path / "usr" / "share" / "locale"

    assert _select_locale_dir(tmp_path, installed_locale) == installed_locale


def test_partial_source_catalogs_do_not_hide_installed_languages(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "po").mkdir()
    german_source = tmp_path / "po" / "de.po"
    shutil.copy2(ROOT / "po" / "de.po", german_source)
    (tmp_path / "po" / "ru.po").touch()
    german_catalog = tmp_path / "locale" / "de" / "LC_MESSAGES"
    german_catalog.mkdir(parents=True)
    subprocess.run([
        "msgfmt", "--check", "--output-file",
        str(german_catalog / f"{DOMAIN}.mo"), str(german_source),
    ], check=True)
    installed_locale = tmp_path / "usr" / "share" / "locale"

    assert _select_locale_dir(tmp_path, installed_locale) == installed_locale


def test_stale_source_catalogs_fall_back_to_installed_catalogs(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "po").mkdir()
    source_catalog = tmp_path / "po" / "ru.po"
    shutil.copy2(ROOT / "po" / "ru.po", source_catalog)
    compiled_catalog = tmp_path / "locale" / "ru" / "LC_MESSAGES" / f"{DOMAIN}.mo"
    compiled_catalog.parent.mkdir(parents=True)
    subprocess.run([
        "msgfmt", "--check", "--output-file",
        str(compiled_catalog), str(source_catalog),
    ], check=True)
    os.utime(compiled_catalog, (0, 0))
    installed_locale = tmp_path / "usr" / "share" / "locale"

    assert _select_locale_dir(tmp_path, installed_locale) == installed_locale


def test_corrupt_source_catalogs_fall_back_to_installed_catalogs(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "po").mkdir()
    source_catalog = tmp_path / "po" / "ru.po"
    source_catalog.touch()
    compiled_catalog = tmp_path / "locale" / "ru" / "LC_MESSAGES" / f"{DOMAIN}.mo"
    compiled_catalog.parent.mkdir(parents=True)
    compiled_catalog.write_bytes(b"not a gettext catalog")
    installed_locale = tmp_path / "usr" / "share" / "locale"

    assert _select_locale_dir(tmp_path, installed_locale) == installed_locale
