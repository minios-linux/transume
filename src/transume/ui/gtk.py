"""Centralized, optional GTK imports."""

from __future__ import annotations

GTK_IMPORT_ERROR: Exception | None = None

try:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Gdk", "4.0")
    from gi.repository import Gdk, Gio, GLib, GObject, Gtk, Pango
except (ImportError, ValueError) as error:  # pragma: no cover - host dependent
    Gdk = Gio = GLib = GObject = Gtk = Pango = None  # type: ignore[assignment]
    GTK_IMPORT_ERROR = error


def require_gtk() -> None:
    """Raise an actionable error when the GTK runtime is unavailable."""
    if GTK_IMPORT_ERROR is not None:
        raise RuntimeError(
            "Transume requires PyGObject and GTK 4.8 or newer "
            "(Debian/Ubuntu packages: python3-gi and gir1.2-gtk-4.0)."
        ) from GTK_IMPORT_ERROR


def set_accessible_label(widget: object, label: str) -> None:
    """Set an AT label when supported by the installed GTK version.

    Gtk.AccessibleProperty/update_property arrived after the oldest GTK4 we
    support.  Tooltips are not an accessibility replacement, but retain useful
    context for older runtimes instead of failing application startup.
    """
    property_type = getattr(Gtk, "AccessibleProperty", None)
    update = getattr(widget, "update_property", None)
    if property_type is not None and callable(update):
        try:
            update([property_type.LABEL], [label])
            return
        except (AttributeError, TypeError):
            pass
    tooltip = getattr(widget, "set_tooltip_text", None)
    if callable(tooltip):
        tooltip(label)


def set_accessible_role(widget: object, role: object) -> None:
    """Set an accessible role only on GTK versions that expose it."""
    setter = getattr(widget, "set_accessible_role", None)
    if callable(setter):
        try:
            setter(role)
        except (AttributeError, TypeError):
            pass
