#!/usr/bin/env python3
"""Headless GTK interaction and qualification checks for the main workflows."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src") if (ROOT / "src").is_dir() else "/usr/lib/transume")

from transume.application import TransumeApplication  # noqa: E402
from transume.images import ImageCandidate, ImageStatus, ImageType, SourceTopology  # noqa: E402
from transume.storage import ConnectionState  # noqa: E402
from transume.ui.gtk import GLib, Gtk  # noqa: E402
from transume.ui.components import ImageCard  # noqa: E402


GEOMETRIES = {(800, 520), (1024, 600), (1180, 640), (1280, 800)}


def parse_geometry(value: str) -> tuple[int, int]:
    try:
        width, height = (int(part) for part in value.lower().split("x", 1))
    except ValueError as error:
        raise argparse.ArgumentTypeError("geometry must be WIDTHxHEIGHT") from error
    if (width, height) not in GEOMETRIES:
        raise argparse.ArgumentTypeError(
            f"geometry must be one of {sorted(GEOMETRIES)}"
        )
    return width, height


def high_contrast_available() -> bool:
    """Only request HighContrast when GTK can actually load its stylesheet."""
    data_dirs = os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share").split(":")
    return any(
        (Path(directory) / "themes" / "HighContrast" / "gtk-4.0" / "gtk.css").is_file()
        for directory in data_dirs
    )


def accessible_label(widget, expected: str) -> None:
    getter = getattr(widget, "get_accessible_property", None)
    property_type = getattr(Gtk, "AccessibleProperty", None)
    if callable(getter) and property_type is not None:
        assert getter(property_type.LABEL) == expected
    elif callable(getattr(widget, "update_property", None)) and property_type is not None:
        # GTK accepted the property in set_accessible_label(), but this PyGObject
        # version does not expose a matching getter. AT-SPI covers the value.
        return
    else:
        # Older GTK retains the label as a tooltip.
        assert widget.get_tooltip_text() == expected


class FakeModel:
    capabilities = None

    def __init__(self, root: Path):
        self.root = root

    def discover(self):
        return None

    def list_devices(self):
        return []

    def list_images(self):
        path = self.root / "example"
        return [
            ImageCandidate(
                "fake", path, "example", "example",
                ImageType.SAVEDISK, ("sda",), ("sda1",), SourceTopology(),
                ("sda1.ext4-ptcl-img",), 1024, datetime.now(timezone.utc),
                datetime.now(timezone.utc), ("zstd",), False, False, (),
                ImageStatus.READY, (),
            )
        ]

    def set_repository(self, _path):
        return None

    def set_storage_location(self, _location):
        return None

    def list_activity(self):
        return []


class FakeStorageManager:
    def __init__(self):
        self.unmounted = []
        self.sessions = []

    def unmount(self, session):
        self.unmounted.append(session)


class MountedSession:
    state = ConnectionState.MOUNTED


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geometry", type=parse_geometry, default=(1180, 640))
    parser.add_argument("--dark", action="store_true", help="assert GTK dark preference")
    parser.add_argument("--high-contrast", action="store_true", help="use HighContrast when installed")
    parser.add_argument("--font-scale", type=float, default=1.0)
    parser.add_argument("--require-scale", type=int, default=1)
    parser.add_argument("--wm-tolerance", type=int, default=0,
                        help="allow window-manager geometry adjustments")
    args = parser.parse_args()
    if args.font_scale < 1:
        parser.error("--font-scale must be at least 1")
    if args.wm_tolerance < 0:
        parser.error("--wm-tolerance must not be negative")
    if args.high_contrast and not high_contrast_available():
        print("SKIP: GTK HighContrast theme is not installed")
        return 0

    requested_width, requested_height = args.geometry
    storage = FakeStorageManager()
    temporary = tempfile.TemporaryDirectory(prefix="transume-gtk-smoke-")
    root = Path(temporary.name)
    image = root / "example"
    image.mkdir()
    (image / "parts").write_text("sda1\n")
    (image / "disk").write_text("sda\n")
    (image / "sda1.ext4-ptcl-img").write_bytes(b"payload")
    app = TransumeApplication(
        FakeModel(root), storage_manager=storage,
        application_id="dev.minios.transume.Smoke",
    )

    # Application.do_activate imports this symbol lazily, so this test-only
    # subclass makes each invocation start at one exact matrix geometry.
    from transume.ui import window as window_module  # noqa: E402
    original_window = window_module.MainWindow

    class QualificationWindow(original_window):
        def __init__(self, *window_args, **window_kwargs):
            super().__init__(*window_args, **window_kwargs)
            self.set_default_size(requested_width, requested_height)

    window_module.MainWindow = QualificationWindow
    failures: list[str] = []

    def checked(callback):
        """Turn asynchronous GTK assertion failures into a failing process status."""
        def run(*callback_args):
            try:
                return callback(*callback_args)
            except AssertionError:
                failures.append(callback.__name__)
                traceback.print_exc()
                app.quit()
                return GLib.SOURCE_REMOVE
        return run

    def verify() -> bool:
        window = app.window
        assert window is not None and window.get_resizable()
        assert window.header_title.get_label() == "Transume"
        actual_geometry = (window.get_width(), window.get_height())
        if actual_geometry == (0, 0):
            return GLib.SOURCE_CONTINUE
        assert all(abs(actual - requested) <= args.wm_tolerance for actual, requested in
                   zip(actual_geometry, args.geometry)), (
            f"requested {args.geometry}, realized {actual_geometry}"
        )
        assert window.get_width() >= 800 and window.get_height() >= 520
        assert window._layout_mode == ("compact" if requested_width < 1240 else "wide")
        assert window.rail.get_visible() == (requested_width >= 1240)
        assert window.navigation_menu.get_visible() == (requested_width < 1240)
        assert window.images_page.compact is (requested_width < 1240)
        assert window.navigation_menu.get_popover() is window.navigation_popover
        assert set(window.compact_nav_buttons) == {item[0] for item in window.NAVIGATION}
        assert window.compact_nav_buttons["dashboard"].has_css_class("is-active")
        assert window.navigate_action.get_state().get_string() == "dashboard"
        window.navigate("restore")
        assert window.header_title.get_label() == "Transume"
        assert window.navigate_action.get_state().get_string() == "restore"
        assert window.compact_nav_buttons["restore"].has_css_class("is-active")
        assert not window.compact_nav_buttons["dashboard"].has_css_class("is-active")
        window.navigate("dashboard")
        assert window.get_surface().get_scale_factor() >= args.require_scale
        settings = Gtk.Settings.get_default()
        assert settings is not None
        settings.set_property("gtk-application-prefer-dark-theme", args.dark)
        assert settings.get_property("gtk-application-prefer-dark-theme") is args.dark
        if args.high_contrast:
            settings.set_property("gtk-theme-name", "HighContrast")
            assert settings.get_property("gtk-theme-name") == "HighContrast"
        base_dpi = settings.get_property("gtk-xft-dpi") or 96 * 1024
        settings.set_property("gtk-xft-dpi", int(base_dpi * args.font_scale))
        assert settings.get_property("gtk-xft-dpi") >= int(base_dpi * args.font_scale)
        assert window.rail.get_hexpand() is False
        assert window.rail.get_hexpand_set() is True
        assert window.stack.get_hhomogeneous() is False
        assert window.stack.get_vhomogeneous() is False
        for editor in window.route_editors:
            assert editor.route.get_orientation() == (
                Gtk.Orientation.VERTICAL if requested_width < 1240 else Gtk.Orientation.HORIZONTAL
            )
            assert editor.advanced_revealer.get_reveal_child() is False
            editor.advanced_toggle.emit("clicked")
            assert editor.advanced_revealer.get_reveal_child() is True
            editor.advanced_toggle.emit("clicked")
        backup = window.route_editors[0]
        long_path = Path("/qualification/" + "/".join(["very-long-storage-location"] * 12))
        backup._set_repository(long_path)
        assert backup.destination.detail.get_label() == str(long_path)
        assert backup.destination.detail.get_ellipsize().value_nick == "end"
        assert backup.destination.detail.get_lines() == 3
        accessible_label(backup.destination.choose, "Choose destination")
        accessible_label(window.nav_buttons["backup"], "Open Backup")
        backup.source.choose.grab_focus()
        assert window.get_focus() is backup.source.choose
        backup.verify_control.set_active(False)
        assert backup.draft.options.verify_image is False
        if hasattr(backup, "encrypt_control"):
            backup.encrypt_control.set_active(True)
            assert backup.draft.options.encrypt is True
        backup.source.choose.emit("clicked")
        assert window.stack.get_visible_child_name() == "picker"
        window.navigate("restore")
        restore = window.route_editors[1]
        restore.source.choose.emit("clicked")
        assert window.stack.get_visible_child_name() == "image-browser"
        browser = window.stack.get_visible_child()
        browser.set_folder(root / "very/long/path/for/a/compact/window")
        assert browser._state == "loading"
        browser.cancel_scan()
        assert browser._state == "initial"
        browser.set_folder(root)
        # Worker completion is deliberately asynchronous; continue in the GTK loop.
        GLib.timeout_add(100, checked(finish_browser), window, restore, browser)
        return GLib.SOURCE_REMOVE

    def finish_browser(window, restore, browser) -> bool:
        if browser._state == "loading":
            return GLib.SOURCE_CONTINUE
        assert browser._state == "ready"
        assert browser.image_rows
        row = browser.image_rows[0][0]
        card = row.get_child()
        assert isinstance(card, ImageCard)
        assert card.action_menu is not None
        action_box = card.action_menu.get_popover().get_child()
        action_count = 0
        action = action_box.get_first_child()
        while action is not None:
            action_count += isinstance(action, Gtk.Button)
            action = action.get_next_sibling()
        assert action_count == 6
        browser.image_list.emit("row-activated", row)
        assert window.stack.get_visible_child_name() == "restore"
        assert restore.selection["source"] is browser.images[0]
        for editor in window.route_editors:
            editor.set_compact(True)
            editor.set_compact(False)
            editor.set_compact(requested_width < 1240)
            assert editor.route.get_orientation() == (
                Gtk.Orientation.VERTICAL if requested_width < 1240 else Gtk.Orientation.HORIZONTAL
            )
        assert window.rail.get_visible() == (requested_width >= 1240)
        assert window.navigation_menu.get_popover() is window.navigation_popover
        # A completion from a closed chooser is never adopted and is unmounted.
        stale = MountedSession()
        window._mounted_location(None, 999, stale, None, lambda _path: None)
        GLib.timeout_add(100, checked(assert_stale_unmounted), window, storage)
        return GLib.SOURCE_REMOVE

    def assert_stale_unmounted(window, storage) -> bool:
        assert storage.unmounted
        window.navigate("backup")
        window.choose_storage_location(lambda _path: None)
        assert window._storage_chooser is not None
        chooser = window._storage_chooser
        assert chooser.kind.has_css_class("styled-dropdown")
        assert chooser.kind.get_factory() is not None
        assert chooser.kind.get_list_factory() is not None
        chooser.kind.set_selected(3)
        chooser.ssh_auth.set_selected(2)
        assert chooser.ssh_fields["password"].get_visible()
        assert not chooser.ssh_identity_button.get_visible()
        chooser.ssh_auth.set_selected(1)
        assert chooser.ssh_identity_button.get_visible()
        assert not chooser.ssh_fields["password"].get_visible()
        chooser.ssh_auth.set_selected(0)
        assert not chooser.ssh_identity_button.get_visible()
        assert not chooser.ssh_fields["password"].get_visible()
        chooser.kind.set_selected(0)
        chooser.local_button.emit("clicked")
        assert chooser._folder_chooser is not None
        chooser._folder_chooser.emit("response", Gtk.ResponseType.CANCEL)
        assert chooser._folder_chooser is None
        chooser.cancel_button.emit("clicked")
        assert window._storage_chooser is None
        window.navigate("images")
        assert window.stack.get_visible_child_name() == "images"
        assert window.images_page.image_cards
        assert window.images_page.image_cards[0].action_menu is not None
        clone = window.route_editors[2]
        clone.clone_rescue_control.set_active(True)
        assert clone.draft.options.rescue is True
        app.lookup_action("about").activate(None)
        about = next(
            item for item in Gtk.Window.list_toplevels()
            if isinstance(item, Gtk.AboutDialog)
        )
        assert about.get_visible()
        about.close()
        assert about not in Gtk.Window.list_toplevels()
        app.lookup_action("settings").activate(None)
        settings = next(
            item for item in Gtk.Window.list_toplevels()
            if isinstance(item, Gtk.Dialog)
            and item.get_title() == "Transume settings"
            and item.get_visible()
        )
        settings.destroy()
        assert settings not in Gtk.Window.list_toplevels()
        window.maximize()
        window.unmaximize()
        app.quit()
        return GLib.SOURCE_REMOVE

    GLib.timeout_add(250, checked(verify))
    GLib.timeout_add_seconds(20, lambda: (app.quit(), GLib.SOURCE_REMOVE)[1])
    status = int(app.run([]))
    return 1 if failures else status


if __name__ == "__main__":
    raise SystemExit(main())
