"""Reusable GTK widgets for routes and model-backed pickers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import unquote, urlparse

from .gtk import Gdk, Gio, GObject, Gtk, Pango, require_gtk, set_accessible_label, set_accessible_role
from ..i18n import _
from ..images import ImageCandidate, ImageStatus, ImageType


def local_path_from_uri(uri: str) -> Path | None:
    """Return a canonical local path, rejecting network and credential URIs."""
    parsed = urlparse(uri.strip())
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        return None
    try:
        return Path(unquote(parsed.path)).resolve(strict=False)
    except (OSError, ValueError):
        return None


def model_value(item: Any, name: str, default: str = "") -> str:
    if isinstance(item, dict):
        value = item.get(name, default)
    else:
        value = getattr(item, name, default)
    return str(value) if value is not None else default


def model_raw(item: Any, name: str, default: Any = None) -> Any:
    return item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)


def _display_size(value: int) -> str:
    size = float(value)
    for unit in (_("B"), _("KiB"), _("MiB"), _("GiB"), _("TiB")):
        if size < 1024 or unit == "TiB":
            template = _("{size:.0f} {unit}") if unit == "B" else _("{size:.1f} {unit}")
            return template.format(size=size, unit=unit)
        size /= 1024
    return _("{size} B").format(size=value)


if Gtk is not None:
    def dropdown_factory(*, popup: bool = False,
                         icons: tuple[str, ...] = ()) -> Gtk.SignalListItemFactory:
        """Render dropdown values with consistent spacing and optional icons."""
        factory = Gtk.SignalListItemFactory()

        def setup(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
            row = Gtk.Box(spacing=10)
            row.add_css_class("dropdown-option" if popup else "dropdown-value")
            if icons:
                icon = Gtk.Image()
                icon.set_pixel_size(18)
                icon.set_size_request(18, 18)
                icon.add_css_class("muted")
                row.append(icon)
            row.append(Gtk.Label(xalign=0, hexpand=True,
                                 ellipsize=Pango.EllipsizeMode.END))
            item.set_child(row)

        def bind(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
            row = item.get_child()
            if icons:
                row.get_first_child().set_from_icon_name(icons[item.get_position()])
            row.get_last_child().set_label(item.get_item().get_string())

        factory.connect("setup", setup)
        factory.connect("bind", bind)
        return factory


    def style_dropdown(control: Gtk.DropDown, *, icons: tuple[str, ...] = ()) -> Gtk.DropDown:
        control.add_css_class("styled-dropdown")
        control.set_factory(dropdown_factory(icons=icons))
        control.set_list_factory(dropdown_factory(popup=True, icons=icons))
        return control


    def dialog_shell(parent: Gtk.Window, title: str, detail: str = "", *,
                     width: int = 480, icon_name: str = "dialog-information-symbolic") -> tuple[Gtk.Dialog, Gtk.Box]:
        """Create the shared Transume dialog header and content surface."""
        dialog = Gtk.Dialog(transient_for=parent, modal=True, title=title)
        dialog.set_default_size(width, 1)
        content = dialog.get_content_area()
        content.set_spacing(16)
        content.set_margin_top(20)
        content.set_margin_bottom(16)
        content.set_margin_start(20)
        content.set_margin_end(20)

        header = Gtk.Box(spacing=12)
        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(24)
        icon.add_css_class("dialog-icon")
        header.append(icon)
        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True)
        labels.append(Gtk.Label(label=title, xalign=0, wrap=True,
                                css_classes=["dialog-title"]))
        if detail:
            labels.append(Gtk.Label(label=detail, xalign=0, wrap=True, selectable=True,
                                    css_classes=["muted"]))
        header.append(labels)
        content.append(header)
        return dialog, content


    def dialog_actions(content: Gtk.Box) -> Gtk.Box:
        actions = Gtk.Box(spacing=8, halign=Gtk.Align.END,
                          css_classes=["dialog-actions"])
        content.append(actions)
        return actions


    def present_message(parent: Gtk.Window, title: str, detail: str, *,
                        close_label: str = _("Close"),
                        primary_label: str | None = None,
                        on_close: Callable[[], None] | None = None,
                        on_primary: Callable[[], None] | None = None,
                        icon_name: str = "dialog-information-symbolic") -> Gtk.Dialog:
        dialog, content = dialog_shell(parent, title, detail, icon_name=icon_name)
        actions = dialog_actions(content)
        close = Gtk.Button(label=close_label)

        def finish(callback: Callable[[], None] | None) -> None:
            dialog.destroy()
            if callback is not None:
                callback()

        close.connect("clicked", lambda _button: finish(on_close))
        actions.append(close)
        if primary_label is not None:
            primary = Gtk.Button(label=primary_label, css_classes=["suggested-action"])
            primary.connect("clicked", lambda _button: finish(on_primary))
            actions.append(primary)
        dialog.present()
        return dialog


    class ImageCard(Gtk.Box):
        """Shared visual summary used by restore selection and image management."""

        __gtype_name__ = "TransumeImageCard"

        def __init__(self, image: ImageCandidate, *, compact: bool = False,
                     action_menu: Gtk.Widget | None = None,
                     notice: str | None = None) -> None:
            super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.image = image
            self.compact = compact
            self.action_menu = action_menu
            self.add_css_class("image-card")
            self.add_css_class("info-card")
            self.add_css_class("image-card-compact" if compact else "image-card-detailed")

            header = Gtk.Box(spacing=10)
            icon = Gtk.Image.new_from_icon_name(
                "drive-multidisk-symbolic" if len(image.source_disks) > 1
                else "drive-harddisk-symbolic"
            )
            icon.set_pixel_size(28 if compact else 32)
            icon.add_css_class("image-card-icon")
            header.append(icon)
            identity = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
            title = Gtk.Label(label=image.name, xalign=0, ellipsize=Pango.EllipsizeMode.END,
                              css_classes=["card-title"])
            title.set_tooltip_text(image.name)
            identity.append(title)
            image_type = {
                ImageType.SAVEDISK: _("Full disk image"),
                ImageType.SAVEPARTS: _("Partition image"),
            }.get(image.image_type, _("Unknown image type"))
            date = image.created_at or image.modified_at
            subtitle = image_type
            if date is not None:
                subtitle = f"{subtitle}  ·  {date.strftime('%Y-%m-%d %H:%M')}"
            identity.append(Gtk.Label(label=subtitle, xalign=0, ellipsize=Pango.EllipsizeMode.END,
                                      css_classes=["muted", "image-card-subtitle"]))
            header.append(identity)
            badges = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
            status = Gtk.Label(label=image.status.replace("-", " ").title(),
                               css_classes=["status-badge", "image-status"])
            if image.status in {ImageStatus.READY, ImageStatus.NEEDS_VERIFICATION}:
                status.add_css_class("success-text")
            else:
                status.add_css_class("warning-text")
            badges.append(status)
            verification = Gtk.Image.new_from_icon_name(
                "emblem-ok-symbolic" if image.verification_current
                else "dialog-question-symbolic"
            )
            verification.add_css_class("success-text" if image.verification_current else "muted")
            verification.set_tooltip_text(
                _("Passed on {date}").format(date=image.verified_at.strftime("%Y-%m-%d %H:%M"))
                if image.verification_current and image.verified_at else _("Not verified")
            )
            badges.append(verification)
            if action_menu is not None:
                badges.append(action_menu)
            header.append(badges)
            self.append(header)

            payload = _display_size(image.payload_size)
            logical = _display_size(image.logical_size) if image.logical_size is not None else _("Unknown")
            size_header = Gtk.Box(spacing=8)
            size_header.append(Gtk.Label(label=_("Image data"), xalign=0, css_classes=["setting-label"]))
            size_header.append(Gtk.Label(label=f"{payload} / {logical}", xalign=1, hexpand=True,
                                         css_classes=["image-size-value"]))
            self.append(size_header)
            size_bar = Gtk.LevelBar(min_value=0, max_value=1)
            ratio = image.payload_size / image.logical_size if image.logical_size else 0
            size_bar.set_value(max(0, min(1, ratio)))
            size_bar.add_css_class("image-size-bar")
            size_bar.set_tooltip_text(
                f"{_('Image data')}: {payload}\n{_('Logical source size')}: {logical}"
            )
            set_accessible_label(size_bar, f"{_('Image data')}: {payload}; {_('Logical source size')}: {logical}")
            self.append(size_bar)

            topology = Gtk.Box(spacing=7)
            topology.append(Gtk.Image.new_from_icon_name("drive-harddisk-symbolic"))
            disks = ", ".join(image.source_disks) or _("Unavailable")
            topology.append(Gtk.Label(label=disks, css_classes=["image-topology-disk"]))
            topology.append(Gtk.Image.new_from_icon_name("go-next-symbolic"))
            partition_box = Gtk.FlowBox(
                selection_mode=Gtk.SelectionMode.NONE, column_spacing=5, row_spacing=4,
                max_children_per_line=8,
            )
            partition_box.set_halign(Gtk.Align.START)
            topology_parts = {part.name: part for part in image.topology.partitions}
            for name in image.source_partitions:
                part = topology_parts.get(name)
                details = " · ".join(value for value in (
                    name, part.filesystem if part else None, part.label if part else None,
                ) if value)
                partition_box.insert(Gtk.Label(label=details, css_classes=["image-chip"]), -1)
            if not image.source_partitions:
                partition_box.insert(Gtk.Label(label=_("None recorded"), css_classes=["image-chip", "muted"]), -1)
            topology.append(partition_box)
            self.append(topology)

            formats = Gtk.FlowBox(
                selection_mode=Gtk.SelectionMode.NONE, column_spacing=5, row_spacing=4,
                max_children_per_line=10,
            )
            formats.set_halign(Gtk.Align.START)
            formats.insert(Gtk.Label(label=image_type, css_classes=["image-chip"]), -1)
            for compression in image.compression or (_("uncompressed"),):
                formats.insert(Gtk.Label(label=compression, css_classes=["image-chip"]), -1)
            if image.lvm.volume_groups:
                formats.insert(Gtk.Label(
                    label=_("LVM: {groups} VG, {volumes} LV").format(
                        groups=len(image.lvm.volume_groups),
                        volumes=len(image.lvm.logical_volumes),
                    ),
                    css_classes=["image-chip"],
                ), -1)
            if image.split and image.split_parts > 1:
                formats.insert(Gtk.Label(
                    label=_("Yes ({parts} parts)").format(parts=image.split_parts),
                    css_classes=["image-chip"],
                ), -1)
            formats.insert(Gtk.Label(
                label=_("Encrypted") if image.encrypted else _("not encrypted"),
                css_classes=["image-chip", "image-chip-secure" if image.encrypted else "muted"],
            ), -1)
            if not compact:
                for checksum in image.checksums:
                    formats.insert(Gtk.Label(label=checksum.upper(), css_classes=["image-chip"]), -1)
            self.append(formats)

            issues = (*image.problems, *image.metadata_warnings)
            if issues:
                issue_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3,
                                    css_classes=["image-issues"])
                for issue in issues[:1] if compact else issues:
                    issue_box.append(Gtk.Label(label=issue.message, xalign=0, wrap=True))
                self.append(issue_box)

            if notice:
                hint = Gtk.Box(spacing=7, css_classes=["explorer-hint"])
                hint.append(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
                hint.append(Gtk.Label(label=notice, xalign=0, wrap=True, hexpand=True,
                                      css_classes=["explorer-reason"]))
                self.append(hint)

            if not compact:
                path = Gtk.Label(label=str(image.path), xalign=0,
                                 ellipsize=Pango.EllipsizeMode.MIDDLE,
                                 css_classes=["muted", "image-card-path"])
                path.set_tooltip_text(str(image.path))
                self.append(path)


    class SelectionCard(Gtk.Box):
        """Keyboard-accessible source, destination, or storage target."""

        __gtype_name__ = "TransumeSelectionCard"

        def __init__(
            self,
            role: str,
            prompt: str,
            icon_name: str,
            on_choose: Callable[[], None],
            on_local_drop: Callable[[Path], None] | None = None,
            step: int = 1,
            choose_label: str = _("Choose"),
        ) -> None:
            super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.add_css_class("route-card")
            self.set_hexpand(True)
            set_accessible_role(self, Gtk.AccessibleRole.GROUP)
            set_accessible_label(self, _("{role}: {prompt}").format(role=role, prompt=prompt))

            self.intro = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            role_header = Gtk.Box(spacing=8)
            step_label = Gtk.Label(label=str(step))
            step_label.add_css_class("step-number")
            role_header.append(step_label)
            role_label = Gtk.Label(label=role.upper(), xalign=0)
            role_label.add_css_class("eyebrow")
            role_header.append(role_label)
            self.intro.append(role_header)

            identity_row = Gtk.Box(spacing=12)
            identity_row.add_css_class("identity-row")
            identity_row.set_size_request(-1, 72)
            icon_frame = Gtk.Box()
            icon_frame.add_css_class("device-icon-frame")
            icon = Gtk.Image.new_from_icon_name(icon_name)
            icon.set_pixel_size(30)
            icon_frame.append(icon)
            identity_row.append(icon_frame)

            identity_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            identity_text.set_hexpand(True)

            self.title = Gtk.Label(
                label=prompt,
                xalign=0,
                wrap=True,
                wrap_mode=Pango.WrapMode.WORD_CHAR,
                max_width_chars=18,
                lines=2,
                ellipsize=Pango.EllipsizeMode.END,
            )
            self.title.add_css_class("card-title")
            identity_text.append(self.title)

            self.detail = Gtk.Label(
                label=_("Nothing selected"),
                xalign=0,
                wrap=True,
                wrap_mode=Pango.WrapMode.WORD_CHAR,
                max_width_chars=20,
                lines=3,
                ellipsize=Pango.EllipsizeMode.END,
                selectable=True,
            )
            self.detail.add_css_class("muted")
            identity_row.append(identity_text)
            self.intro.append(identity_row)
            self.append(self.intro)

            self.append(Gtk.Separator())

            details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            details.add_css_class("card-details")
            details.set_vexpand(True)
            details.append(self.detail)

            self.meta = Gtk.Box(spacing=6)
            self.meta.set_visible(False)
            self.status_badge = Gtk.Label(label=_("SELECTED"))
            self.status_badge.add_css_class("status-badge")
            self.meta.append(self.status_badge)
            self.meta_note = Gtk.Label(
                xalign=0,
                wrap=True,
                wrap_mode=Pango.WrapMode.WORD_CHAR,
                max_width_chars=22,
                lines=2,
                ellipsize=Pango.EllipsizeMode.END,
                css_classes=["health-label"],
            )
            self.meta.append(self.meta_note)
            details.append(self.meta)
            self.append(details)

            self.choose = Gtk.Button(label=choose_label)
            self.choose.set_halign(Gtk.Align.FILL)
            self.choose.set_hexpand(True)
            set_accessible_role(self.choose, Gtk.AccessibleRole.BUTTON)
            self.choose.add_css_class("card-action")
            set_accessible_label(self.choose, _("Choose {role}").format(role=role.lower()))
            self.choose.connect("clicked", lambda _button: on_choose())
            self.append(self.choose)

            if on_local_drop is not None:
                target = Gtk.DropTarget.new(GObject.TYPE_STRING, Gdk.DragAction.COPY)
                target.connect("enter", self._drop_enter)
                target.connect("leave", self._drop_leave)
                target.connect("drop", self._drop, on_local_drop)
                self.add_controller(target)

        def _drop_enter(self, _target: Any, _x: float, _y: float) -> Any:
            self.add_css_class("drop-active")
            return Gdk.DragAction.COPY

        def _drop_leave(self, _target: Any) -> None:
            self.remove_css_class("drop-active")

        def _drop(
            self,
            _target: Any,
            value: str,
            _x: float,
            _y: float,
            callback: Callable[[Path], None],
        ) -> bool:
            self.remove_css_class("drop-active")
            # text/uri-list may contain comments and multiple paths. Drafts accept
            # the first local path; validation remains the model's responsibility.
            for line in value.splitlines():
                if not line or line.startswith("#"):
                    continue
                path = local_path_from_uri(line)
                if path is not None:
                    callback(path)
                    return True
            return False

        def set_selection(self, title: str, detail: str, metadata: str = "") -> None:
            self.title.set_label(title)
            self.title.set_tooltip_text(title)
            self.detail.set_label(detail)
            self.detail.set_tooltip_text(detail)
            self.choose.set_label(_("Change"))
            self.meta_note.set_label(metadata)
            self.meta_note.set_tooltip_text(metadata or None)
            self.meta_note.set_visible(bool(metadata))
            self.meta.set_visible(True)
            self.add_css_class("is-selected")
            accessible = _("Selected {title}. {detail}").format(title=title, detail=detail)
            if metadata:
                accessible += _(". {metadata}").format(metadata=metadata)
            set_accessible_label(self, accessible)


    class ItemPicker(Gtk.Box):
        """In-window picker which accepts plain model objects or mappings."""

        __gtype_name__ = "TransumeItemPicker"

        def __init__(
            self,
            title: str,
            empty_text: str,
            items: Iterable[Any],
            on_select: Callable[[Any], None],
            on_back: Callable[[], None],
            selection_role: str = "source",
        ) -> None:
            super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            self.add_css_class("page")

            heading = Gtk.Box(spacing=12)
            back = Gtk.Button.new_from_icon_name("go-previous-symbolic")
            back.set_tooltip_text(_("Return to operation"))
            set_accessible_label(back, _("Go back"))
            back.connect("clicked", lambda _button: on_back())
            heading.append(back)
            label = Gtk.Label(label=title, xalign=0)
            label.add_css_class("page-title")
            heading.append(label)
            self.append(heading)

            search = Gtk.SearchEntry(placeholder_text=_("Search model, label, serial, or path"))
            set_accessible_label(search, _("Search {title}").format(title=title.lower()))
            self.append(search)

            rows = list(items)
            list_box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            list_box.add_css_class("boxed-list")
            list_scroll = Gtk.ScrolledWindow(
                hscrollbar_policy=Gtk.PolicyType.NEVER,
                vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
                vexpand=True,
            )
            list_scroll.set_child(list_box)
            self.append(list_scroll)

            if not rows:
                empty = Gtk.Label(label=empty_text, wrap=True, justify=Gtk.Justification.CENTER)
                empty.add_css_class("empty-state")
                list_box.append(empty)

            widgets: list[tuple[Gtk.Widget, str]] = []
            for item in rows:
                title_text = model_value(item, "name") or model_value(item, "model", _("Unknown device"))
                path = model_value(item, "path") or model_value(item, "repository")
                size = model_value(item, "size")
                if not size:
                    payload_size = model_raw(item, "payload_size")
                    if isinstance(payload_size, int):
                        size = _display_size(payload_size)
                status = model_value(item, "status")
                status = status.replace("-", " ").title()
                selectable_name = "selectable_destination" if selection_role == "destination" else "selectable_source"
                selectable = bool(model_raw(item, selectable_name, True))
                button = Gtk.Button()
                button.add_css_class("picker-row")
                button.set_sensitive(selectable)
                content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                icon_name = (
                    "drive-harddisk-symbolic" if path.startswith("/dev/")
                    else "folder-pictures-symbolic"
                )
                icon = Gtk.Image.new_from_icon_name(icon_name)
                icon.set_pixel_size(24)
                icon.add_css_class("picker-icon")
                content.append(icon)
                text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
                text.set_hexpand(True)
                name = Gtk.Label(label=title_text, xalign=0)
                name.add_css_class("card-title")
                text.append(name)
                detail = Gtk.Label(label=" · ".join(x for x in (path, size) if x), xalign=0)
                detail.add_css_class("muted")
                text.append(detail)
                content.append(text)
                if status:
                    status_label = Gtk.Label(label=status, xalign=1)
                    status_label.add_css_class("picker-status")
                    content.append(status_label)
                button.set_child(content)
                accessible = (
                    _("Select {title}").format(title=title_text)
                    if selectable
                    else _("{title} unavailable: {status}").format(
                        title=title_text, status=status
                    )
                )
                set_accessible_label(button, accessible)
                button.connect("clicked", lambda _button, selected=item: on_select(selected))
                list_box.append(button)
                widgets.append((button, "{title} {path}".format(title=title_text, path=path).casefold()))

            def filter_rows(entry: Gtk.SearchEntry) -> None:
                query = entry.get_text().casefold()
                for widget, searchable in widgets:
                    widget.set_visible(query in searchable)

            search.connect("search-changed", filter_rows)

else:
    def _gtk_unavailable(*_args: Any, **_kwargs: Any) -> Any:  # pragma: no cover
        require_gtk()

    dropdown_factory = style_dropdown = dialog_shell = dialog_actions = present_message = _gtk_unavailable

    class SelectionCard:  # pragma: no cover - import-only fallback
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            require_gtk()

    class ItemPicker(SelectionCard):
        pass

    class ImageCard(SelectionCard):
        pass
