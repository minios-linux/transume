import configparser
import pathlib
import unittest
import xml.etree.ElementTree as ET

from transume.application import _prefers_dark
from transume import i18n


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = "/usr/lib/transume/transume-runner"


class MetadataTests(unittest.TestCase):
    def test_system_color_scheme_mapping(self):
        self.assertTrue(_prefers_dark("prefer-dark"))
        self.assertFalse(_prefers_dark("default"))
        self.assertFalse(_prefers_dark("prefer-light"))

    def test_translation_domain_and_locale_paths(self):
        self.assertEqual(i18n.DOMAIN, "transume")
        self.assertEqual(i18n.REPOSITORY_LOCALE_DIR, ROOT / "locale")
        self.assertEqual(i18n.INSTALLED_LOCALE_DIR, pathlib.Path("/usr/share/locale"))

    def test_desktop_entry(self):
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read(
            ROOT / "data/dev.minios.transume.desktop", encoding="utf-8"
        )
        entry = parser["Desktop Entry"]
        self.assertEqual(entry["Type"], "Application")
        self.assertEqual(entry["Exec"], "transume")
        self.assertEqual(entry["Icon"], "transume")
        self.assertEqual(entry["Terminal"], "false")

    def test_policy_actions_use_namespace_and_exact_runner(self):
        root = ET.parse(
            ROOT / "data/polkit/dev.minios.transume.policy"
        ).getroot()
        actions = root.findall("action")
        self.assertEqual(len(actions), 3)
        expected_argv = {"mount", "check", "write"}
        actual_argv = set()
        for action in actions:
            self.assertTrue(action.attrib["id"].startswith("dev.minios.transume."))
            annotation = action.find(
                "annotate[@key='org.freedesktop.policykit.exec.path']"
            )
            self.assertIsNotNone(annotation)
            self.assertEqual(annotation.text, RUNNER)
            argv = action.find("annotate[@key='org.freedesktop.policykit.exec.argv1']")
            self.assertIsNotNone(argv)
            actual_argv.add(argv.text)
        self.assertEqual(actual_argv, expected_argv)

    def test_install_metadata_uses_reserved_paths(self):
        rules = (ROOT / "debian/rules").read_text(encoding="utf-8")
        install = (ROOT / "debian/transume.install").read_text(encoding="utf-8")
        self.assertIn("usr/lib/transume", install)
        self.assertIn("usr/share/transume", install)
        self.assertIn("usr/bin", install)
        self.assertIn("locale usr/share", install)
        self.assertNotIn("cp -a", rules)

    def test_desktop_identity_matches_installed_icon_and_metainfo(self):
        install = (ROOT / "debian/transume.install").read_text(encoding="utf-8")
        self.assertIn("data/dev.minios.transume.desktop usr/share/applications", install)
        self.assertIn("data/icons/hicolor/* usr/share/icons/hicolor", install)
        self.assertIn("data/pixmaps/transume-logo.svg usr/share/pixmaps", install)
        for size in (16, 22, 24, 32, 48, 64, 96, 128):
            self.assertTrue(
                (ROOT / f"data/icons/hicolor/{size}x{size}/apps/transume.svg").is_file()
            )
        self.assertTrue(
            (ROOT / "data/icons/hicolor/symbolic/apps/transume-symbolic.svg").is_file()
        )
        metainfo = ET.parse(
            ROOT / "data/dev.minios.transume.metainfo.xml"
        ).getroot()
        self.assertEqual(metainfo.findtext("id"), "dev.minios.transume")
        self.assertEqual(
            metainfo.find("launchable").text,
            "dev.minios.transume.desktop",
        )

    def test_package_is_architecture_independent(self):
        control = (ROOT / "debian/control").read_text(encoding="utf-8")
        self.assertIn("Package: transume", control)
        self.assertIn("Architecture: all", control)
        self.assertIn("python3 (>= 3.13)", control)
        self.assertIn("clonezilla (>= 5.9.9-1)", control)
        self.assertIn("partclone (>= 0.3.36+repack-1)", control)
        self.assertIn("partclone-nbd (>= 0.0.4-1)", control)
        self.assertIn("nbdkit (>= 1.42.3-1)", control)
        self.assertIn("nbd-client,", control)
        binary = control.split("Package: transume", 1)[1]
        runtime = binary.split("Depends:", 1)[1].split("Description:", 1)[0]
        self.assertNotIn("(=", runtime)
        self.assertNotIn("partclone-utils", control)
        self.assertIn("gir1.2-gtk-4.0 (>= 4.18)", control)
        self.assertNotIn("gir1.2-gtk-3.0", control)

    def test_python_contract_is_debian_13(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('requires-python = ">=3.13"', project)


if __name__ == "__main__":
    unittest.main()
