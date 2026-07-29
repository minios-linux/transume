import gettext

from transume.i18n import DOMAIN, REPOSITORY_LOCALE_DIR


def test_russian_catalog_is_compiled_and_loadable():
    catalog = REPOSITORY_LOCALE_DIR / "ru" / "LC_MESSAGES" / f"{DOMAIN}.mo"
    assert catalog.is_file()
    translation = gettext.translation(DOMAIN, localedir=REPOSITORY_LOCALE_DIR, languages=["ru"])
    assert translation.gettext("Backup") == "Резервное копирование"
