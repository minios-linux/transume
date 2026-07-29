"""Transume GTK application entry point."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .ui.gtk import Gio, Gtk, require_gtk
from .i18n import _
from .ui.components import present_message

APPLICATION_ID = "dev.minios.transume"


def _prefers_dark(color_scheme: str) -> bool:
    return color_scheme == "prefer-dark"


def _data_file(relative: str) -> Path:
    source_root = Path(__file__).resolve().parents[2]
    candidates = (
        source_root / "data" / relative,
        Path("/usr/share/transume") / relative,
    )
    return next((path for path in candidates if path.exists()), candidates[0])


def _logo_file() -> Path:
    source = Path(__file__).resolve().parents[2] / "data" / "pixmaps" / "transume-logo.svg"
    installed = Path("/usr/share/pixmaps/transume-logo.svg")
    return source if source.exists() else installed


if Gtk is not None:
    class TransumeApplication(Gtk.Application):
        def __init__(self, model: Any = None, storage_manager: Any = None,
                     *, application_id: str = APPLICATION_ID) -> None:
            super().__init__(application_id=application_id, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
            if model is None:
                from .model import ApplicationModel

                model = ApplicationModel()
            self.model = model
            self.storage_manager = storage_manager
            self.window = None
            self._interface_settings = None

        def do_startup(self) -> None:
            Gtk.Application.do_startup(self)
            self._follow_system_color_scheme()
            self._load_css()
            about = Gio.SimpleAction.new("about", None)
            about.connect("activate", self._show_about)
            self.add_action(about)
            shortcuts = Gio.SimpleAction.new("shortcuts", None)
            shortcuts.connect("activate", self._show_shortcuts)
            self.add_action(shortcuts)
            settings = Gio.SimpleAction.new("settings", None)
            settings.connect("activate", self._show_settings)
            self.add_action(settings)
            quit_action = Gio.SimpleAction.new("quit", None)
            quit_action.connect("activate", lambda _action, _parameter: self.quit())
            self.add_action(quit_action)
            self.set_accels_for_action("app.quit", ["<Primary>q"])

        def _follow_system_color_scheme(self) -> None:
            schema_source = Gio.SettingsSchemaSource.get_default()
            if schema_source is None:
                return
            schema = schema_source.lookup("org.gnome.desktop.interface", True)
            if schema is None or not schema.has_key("color-scheme"):
                return
            self._interface_settings = Gio.Settings.new_full(schema, None, None)

            def update(settings: Gio.Settings, _key: str = "color-scheme") -> None:
                gtk_settings = Gtk.Settings.get_default()
                if gtk_settings is not None:
                    gtk_settings.set_property(
                        "gtk-application-prefer-dark-theme",
                        _prefers_dark(settings.get_string("color-scheme")),
                    )

            update(self._interface_settings)
            self._interface_settings.connect("changed::color-scheme", update)

        def do_activate(self) -> None:
            if self.window is None:
                from .ui.window import MainWindow

                discover = getattr(self.model, "discover", None)
                if callable(discover):
                    try:
                        discover()
                    except Exception as error:
                        print(
                            _("Transume: capability discovery failed: {error}").format(error=error),
                            file=sys.stderr,
                        )
                self.window = MainWindow(self, self.model, self.storage_manager)
            self.window.present()

        def _load_css(self) -> None:
            path = _data_file("css/style.css")
            provider = Gtk.CssProvider()
            try:
                provider.load_from_path(str(path))
                from .ui.gtk import Gdk

                display = Gdk.Display.get_default()
                if display is not None:
                    Gtk.StyleContext.add_provider_for_display(
                        display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                    )
            except Exception as error:
                print(
                    _("Transume: could not load stylesheet: {error}").format(error=error),
                    file=sys.stderr,
                )

        def _show_about(self, _action: Gio.SimpleAction, _parameter: Any) -> None:
            dialog = Gtk.AboutDialog(transient_for=self.window, modal=True)
            dialog.set_program_name("Transume")
            dialog.set_version(__version__)
            dialog.set_authors(["crims0n <crims0n@minios.dev>"])
            dialog.set_copyright("Copyright (C) 2026 MiniOS Linux")
            dialog.set_comments(_("A careful GTK frontend for Clonezilla workflows"))
            from .ui.gtk import Gdk

            dialog.set_logo(Gdk.Texture.new_from_filename(str(_logo_file())))
            dialog.present()

        def _show_settings(self, _action: Gio.SimpleAction, _parameter: Any) -> None:
            present_message(
                self.window, _("Transume settings"),
                _(
                    "Appearance follows the system GTK theme. Operation-specific "
                    "settings are available in the right-hand panel."
                ),
                icon_name="emblem-system-symbolic",
            )

        def _show_shortcuts(self, _action: Gio.SimpleAction, _parameter: Any) -> None:
            present_message(
                self.window, _("Keyboard shortcuts"),
                _("Use Tab and Shift+Tab to move between controls. Press Ctrl+Q to quit."),
                icon_name="preferences-desktop-keyboard-shortcuts-symbolic",
            )

else:
    class TransumeApplication:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            require_gtk()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        require_gtk()
    except RuntimeError as error:
        print(_("transume: {error}").format(error=error), file=sys.stderr)
        return 1
    from .model import ApplicationModel

    application = TransumeApplication(ApplicationModel())
    return int(application.run(list(argv) if argv is not None else sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
