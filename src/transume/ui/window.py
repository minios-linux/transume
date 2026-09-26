"""Single-window application shell and navigation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import threading
from typing import Any, Callable

from .components import ItemPicker, dialog_actions, dialog_shell, present_message
from .gtk import Gio, GLib, Gtk, Pango, require_gtk, set_accessible_label
from .pages import AboutPage, ActivityPage, HomePage, ImageBrowserPage, ImagesPage, ReviewPage, RestoreMappingPage, RouteEditorPage, StorageLocationChooser
from ..client import AuthorizationError, ImageExplorerClient, SecretValue, run_spec
from ..activity import LogStore
from ..controller import build_draft
from ..draft import JobDraft
from ..preflight import PreflightService, Severity
from ..images import ImageCandidate
from ..storage import (ConnectionState, MountOwnership, StorageError, StorageKind,
                       StorageLocation, StorageManager, prepare_smb_subfolder)
from ..i18n import _


if Gtk is not None:
    class MainWindow(Gtk.ApplicationWindow):
        __gtype_name__ = "TransumeMainWindow"

        NAVIGATION = (
            ("dashboard", _("Home"), "go-home-symbolic"),
            ("backup", _("Backup"), "document-save-symbolic"),
            ("restore", _("Restoration"), "document-revert-symbolic"),
            ("clone", _("Clone"), "edit-copy-symbolic"),
            ("images", _("Images"), "folder-pictures-symbolic"),
            ("activity", _("Activity"), "view-list-symbolic"),
            ("about", _("About"), "help-about-symbolic"),
        )

        def __init__(self, application: Gtk.Application, model: Any = None, storage_manager: StorageManager | None = None) -> None:
            super().__init__(application=application, title="Transume")
            self.model = model
            self.set_default_size(1024, 580)
            self.set_size_request(800, 520)
            self.set_resizable(True)
            self._layout_mode = ""
            self.route_editors: list[RouteEditorPage] = []
            self.storage_manager = storage_manager or StorageManager()
            self.explorer_client = ImageExplorerClient()
            self._storage_chooser: StorageLocationChooser | None = None
            self._storage_selector: Gtk.Dialog | None = None
            self._storage_session = None
            self._storage_request = 0
            self._closing = False
            self._cleanup_started = False
            self._job_cancel: threading.Event | None = None
            self._job_storage_session = None

            header = Gtk.HeaderBar()
            header.set_show_title_buttons(True)
            self.header_title = Gtk.Label(label="Transume")
            self.header_title.add_css_class("header-title")
            header.set_title_widget(self.header_title)
            self.home_button = Gtk.Button(icon_name="go-home-symbolic", tooltip_text=_("Home"))
            set_accessible_label(self.home_button, _("Open Home"))
            self.home_button.connect("clicked", lambda _button: self.navigate("dashboard"))
            header.pack_start(self.home_button)
            self.navigation_menu = Gtk.MenuButton(
                icon_name="open-menu-symbolic", tooltip_text=_("Navigation")
            )
            self.navigation_menu.set_visible(False)
            set_accessible_label(self.navigation_menu, _("Navigation menu"))
            self.navigation_popover = Gtk.Popover(autohide=True, has_arrow=False)
            compact_navigation = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            compact_navigation.add_css_class("compact-navigation")
            self.compact_nav_buttons: dict[str, Gtk.Button] = {}
            for name, label, icon_name in self.NAVIGATION:
                button = Gtk.Button()
                button.add_css_class("flat")
                button.add_css_class("compact-nav-item")
                content = Gtk.Box(spacing=10)
                icon = Gtk.Image.new_from_icon_name(icon_name)
                icon.set_pixel_size(18)
                content.append(icon)
                content.append(Gtk.Label(label=label, xalign=0, hexpand=True))
                button.set_child(content)
                set_accessible_label(button, _("Open {label}").format(label=label))
                button.connect("clicked", lambda _button, target=name: self._navigate_compact(target))
                if name == "about":
                    compact_navigation.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
                compact_navigation.append(button)
                self.compact_nav_buttons[name] = button
            self.navigation_popover.set_child(compact_navigation)
            self.navigation_menu.set_popover(self.navigation_popover)
            self.navigate_action = Gio.SimpleAction.new_stateful(
                "navigate", GLib.VariantType.new("s"), GLib.Variant.new_string("dashboard")
            )
            self.navigate_action.connect(
                "activate", lambda _action, value: self.navigate(value.get_string())
            )
            self.add_action(self.navigate_action)
            self._update_navigation_menu("dashboard")
            header.pack_start(self.navigation_menu)
            self.set_titlebar(header)

            root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            self.set_child(root)
            self.rail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            self.rail.add_css_class("navigation-rail")
            # Child labels expand within buttons, but must not make the whole rail
            # compete with page content for horizontal space.
            self.rail.set_hexpand(False)
            self.nav_buttons: dict[str, Gtk.ToggleButton] = {}
            group: Gtk.ToggleButton | None = None
            for name, label, icon_name in self.NAVIGATION:
                button = Gtk.ToggleButton()
                button.add_css_class("flat")
                button.add_css_class("nav-button")
                if group is not None:
                    button.set_group(group)
                else:
                    group = button
                content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                icon = Gtk.Image.new_from_icon_name(icon_name)
                icon.set_pixel_size(20)
                content.append(icon)
                content.append(Gtk.Label(label=label, xalign=0, hexpand=True))
                button.set_child(content)
                button.set_tooltip_text(label)
                set_accessible_label(button, _("Open {label}").format(label=label))
                button.connect("clicked", lambda selected, target=name: selected.get_active() and self.navigate(target))
                if name != "about":
                    self.rail.append(button)
                self.nav_buttons[name] = button
            self.rail.append(Gtk.Box(vexpand=True))
            self.rail.append(self.nav_buttons["about"])
            root.append(self.rail)

            self.stack = Gtk.Stack(
                transition_type=Gtk.StackTransitionType.CROSSFADE,
                transition_duration=180,
                hhomogeneous=False,
                vhomogeneous=False,
                hexpand=True,
                vexpand=True,
            )
            root.append(self.stack)
            self.home_page = HomePage(self.navigate)
            self._add_page("dashboard", self.home_page)
            self.about_page = AboutPage(self.navigate, model)
            self._add_page("about", self.about_page)
            self.route_card_widths = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)
            self.context_panel_widths = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)
            for operation in ("backup", "restore", "clone"):
                editor = RouteEditorPage(
                     operation, model, self.open_picker, self.choose_storage_location,
                    self.choose_image,
                    self.open_review, self.route_card_widths,
                     self.context_panel_widths,
                    on_back=lambda: self.navigate("dashboard"),
                    open_restore_mapping=self.open_restore_mapping,
                )
                self.route_editors.append(editor)
                self._add_page(operation, editor)
            self.images_page = ImagesPage(
                model, self.choose_storage_location, self.open_picker, self.open_review,
                self.explorer_client, self._restore_image,
            )
            self._add_page("images", self.images_page)
            self.activity_page = ActivityPage(model)
            self._add_page("activity", self.activity_page)
            self.navigate("dashboard")
            self.connect("realize", self._watch_surface_size)
            self.connect("close-request", self._close_request)

        def _watch_surface_size(self, *_args: Any) -> None:
            surface = self.get_surface()
            if surface is not None:
                surface.connect("layout", self._size_changed)
            GLib.idle_add(self._size_changed)

        def _close_request(self, *_args: Any) -> bool:
            if self._job_cancel is not None:
                self._job_cancel.set()
            if self._closing:
                return True
            self._closing = True
            self._finish_close_when_safe()
            return True

        def _finish_close_when_safe(self) -> bool:
            if self._job_cancel is not None or self.images_page.explorer_pending:
                GLib.timeout_add(100, self._finish_close_when_safe)
                return GLib.SOURCE_REMOVE
            if self._cleanup_started:
                return GLib.SOURCE_REMOVE
            self._cleanup_started = True
            def cleanup() -> None:
                errors = (*self.images_page.cleanup_explorer(), *self.storage_manager.cleanup_owned())
                GLib.idle_add(self._cleanup_complete, errors)
            threading.Thread(target=cleanup, name="transume-storage-cleanup", daemon=True).start()
            return GLib.SOURCE_REMOVE

        def _cleanup_complete(self, errors: tuple[str, ...]) -> bool:
            if errors:
                present_message(
                    self, _("Storage cleanup failed"), "\n".join(errors),
                    on_close=self.destroy, icon_name="dialog-warning-symbolic",
                )
            else:
                self.destroy()
            return GLib.SOURCE_REMOVE

        def _job_finished(self) -> bool:
            self._job_cancel = None
            self._job_storage_session = None
            if self._closing:
                self._finish_close_when_safe()
            return GLib.SOURCE_REMOVE

        def _add_page(self, name: str, child: Gtk.Widget) -> None:
            self.stack.add_named(child, name)

        def navigate(self, name: str) -> None:
            self.stack.set_visible_child_name(name)
            if name in self.nav_buttons:
                self.nav_buttons[name].set_active(True)
                self.navigate_action.set_state(GLib.Variant.new_string(name))
            self._update_navigation_menu(name)

        def _navigate_compact(self, name: str) -> None:
            self.navigation_popover.popdown()
            self.navigate(name)

        def _update_navigation_menu(self, current: str) -> None:
            for name, button in self.compact_nav_buttons.items():
                if name == current:
                    button.add_css_class("is-active")
                else:
                    button.remove_css_class("is-active")

        def _size_changed(self, *_args: Any) -> None:
            width, height = self.get_width(), self.get_height()
            # Three route cards, the settings panel and navigation cannot fit
            # safely below this width, especially with translated labels.
            mode = "compact" if width < 1700 else "wide"
            if mode != self._layout_mode:
                if self._layout_mode:
                    self.remove_css_class(self._layout_mode)
                self.add_css_class(mode)
                self._layout_mode = mode
                self.rail.set_visible(mode == "wide")
                self.navigation_menu.set_visible(mode == "compact")
                self.about_page.set_compact(mode == "compact")
                for editor in self.route_editors:
                    editor.set_compact(mode == "compact")
                self.images_page.set_compact(mode == "compact")
            if height < 620:
                self.add_css_class("short")
            else:
                self.remove_css_class("short")

        def open_picker(self, kind: str, title: str, on_select: Callable[[Any], None]) -> None:
            method = "list_images" if kind == "images" else "list_devices"
            callback = getattr(self.model, method, None) if self.model is not None else None
            error_message = None
            try:
                if not callable(callback):
                    raise RuntimeError(_("{method} is unavailable").format(method=method))
                items = list(callback())
            except Exception as error:
                items = []
                error_message = _("Could not scan items: {error}").format(error=error)
            previous = self.stack.get_visible_child_name() or "dashboard"

            def back() -> None:
                self.navigate(previous)

            def selected(item: Any) -> None:
                on_select(item)
                self.navigate(previous)

            role = "destination" if "destination" in title.casefold() else "source"
            if error_message:
                empty_text = error_message
            elif kind == "images":
                empty_text = (
                    _("No Clonezilla images were found in this folder. "
                      "Return and choose a different folder.")
                )
            else:
                empty_text = _("No storage devices are available.")
            picker = ItemPicker(title, empty_text, items, selected, back, role)
            old = self.stack.get_child_by_name("picker")
            if old is not None:
                self.stack.remove(old)
            self.stack.add_named(picker, "picker")
            self.stack.set_visible_child_name("picker")

        def choose_storage_location(self, callback: Callable[[Path], None]) -> None:
            if self._job_cancel is not None:
                present_message(
                    self, _("Storage is in use"),
                    _("Wait for the current operation and storage cleanup to finish."),
                    icon_name="dialog-warning-symbolic",
                )
                return
            connected = [session for session in self.storage_manager.sessions
                         if session.state is ConnectionState.MOUNTED]
            if connected:
                self._show_storage_sessions(callback, connected)
                return
            self._connect_storage_location(callback)

        def _show_storage_sessions(self, callback: Callable[[Path], None],
                                   sessions: list[Any]) -> None:
            if self._storage_selector is not None:
                self._storage_selector.present()
                return
            dialog, content = dialog_shell(
                self, _("Storage locations"),
                _("Choose a connected storage location or connect another one."),
                width=560, icon_name="drive-multidisk-symbolic",
            )
            self._storage_selector = dialog
            listing = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            for session in sessions:
                location = session.effective_location or session.location
                row = Gtk.Box(spacing=10, css_classes=["info-card", "storage-session-row"])
                row.append(Gtk.Image.new_from_icon_name(
                    "folder-symbolic" if location.kind is StorageKind.LOCAL_FOLDER
                    else "folder-remote-symbolic"
                ))
                labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
                title = location.host or Path(location.root).name or location.root
                labels.append(Gtk.Label(label=title, xalign=0, css_classes=["card-title"]))
                labels.append(Gtk.Label(label=str(location.root), xalign=0,
                                        ellipsize=Pango.EllipsizeMode.MIDDLE,
                                        css_classes=["muted"]))
                row.append(labels)
                use = Gtk.Button(label=_("Use this storage"), css_classes=["suggested-action"])
                use.connect("clicked", lambda _button, item=session: self._select_storage_session(item, callback, dialog))
                row.append(use)
                disconnect = Gtk.Button(label=_("Forget") if session.ownership is MountOwnership.EXTERNAL else _("Disconnect"))
                disconnect.connect("clicked", lambda button, item=session: self._disconnect_storage_session(item, button, dialog, callback))
                row.append(disconnect)
                listing.append(row)
            content.append(listing)
            actions = dialog_actions(content)
            cancel = Gtk.Button(label=_("Cancel"))
            cancel.connect("clicked", lambda _button: self._close_storage_selector(dialog))
            connect = Gtk.Button(label=_("Connect another"))
            connect.connect("clicked", lambda _button: (self._close_storage_selector(dialog), self._connect_storage_location(callback)))
            actions.append(cancel)
            actions.append(connect)
            dialog.connect("close-request", lambda _dialog: (self._close_storage_selector(dialog), True)[1])
            dialog.present()

        def _close_storage_selector(self, dialog: Gtk.Dialog) -> None:
            if self._storage_selector is dialog:
                self._storage_selector = None
            dialog.destroy()

        def _select_storage_session(self, session: Any, callback: Callable[[Path], None],
                                    dialog: Gtk.Dialog) -> None:
            location = session.effective_location or session.location
            self._set_model_location(location)
            self._storage_session = session
            self._close_storage_selector(dialog)
            callback(Path(location.root))

        def _disconnect_storage_session(self, session: Any, button: Gtk.Button,
                                        dialog: Gtk.Dialog, callback: Callable[[Path], None]) -> None:
            button.set_sensitive(False)
            if session.ownership is MountOwnership.EXTERNAL:
                if session in self.storage_manager.sessions:
                    self.storage_manager.sessions.remove(session)
                self._storage_disconnected(session, dialog, callback)
                return
            def worker() -> None:
                try:
                    self.storage_manager.unmount(session)
                    GLib.idle_add(self._storage_disconnected, session, dialog, callback)
                except StorageError as error:
                    GLib.idle_add(self._storage_disconnect_failed, button, str(error))
            threading.Thread(target=worker, name="transume-storage-disconnect", daemon=True).start()

        def _storage_disconnected(self, session: Any, dialog: Gtk.Dialog,
                                  callback: Callable[[Path], None]) -> bool:
            if session in self.storage_manager.sessions:
                self.storage_manager.sessions.remove(session)
            if self._storage_session is session:
                self._storage_session = None
                clear = getattr(self.model, "clear_current_location", None)
                if callable(clear):
                    clear()
            self._close_storage_selector(dialog)
            remaining = [item for item in self.storage_manager.sessions
                         if item.state is ConnectionState.MOUNTED]
            if remaining:
                self._show_storage_sessions(callback, remaining)
            else:
                self._connect_storage_location(callback)
            return GLib.SOURCE_REMOVE

        @staticmethod
        def _storage_disconnect_failed(button: Gtk.Button, detail: str) -> bool:
            button.set_sensitive(True)
            button.set_tooltip_text(detail)
            return GLib.SOURCE_REMOVE

        def _connect_storage_location(self, callback: Callable[[Path], None]) -> None:
            if self._storage_chooser is not None:
                self._storage_chooser.present()
                return
            self._storage_request += 1
            request = self._storage_request
            chooser: StorageLocationChooser | None = None
            def cancelled() -> None:
                if self._storage_chooser is chooser:
                    self._storage_chooser = None
            def selected(location: StorageLocation, credentials: dict[str, str]) -> None:
                if location.kind is StorageKind.LOCAL_FOLDER:
                    self._use_external_location(location, callback, chooser, request)
                    return
                session = self.storage_manager.register(location, MountOwnership.TRANSUME)
                def worker() -> None:
                    try:
                        self.storage_manager.mount(session, credentials)
                        root = Path(session.location.root)
                        if location.kind is StorageKind.SMB and location.endpoint != "/":
                            root = prepare_smb_subfolder(root, location.endpoint)
                        GLib.idle_add(self._mounted_location, chooser, request, session, replace(session.location, root=str(root)), callback)
                    except FileNotFoundError:
                        GLib.idle_add(self._storage_failed, chooser, request, session,
                                      _("Requested storage folder was not found."))
                    except PermissionError:
                        GLib.idle_add(self._storage_failed, chooser, request, session,
                                      _("Storage folder is not accessible."))
                    except Exception as error:
                        GLib.idle_add(self._storage_failed, chooser, request, session, str(error))
                threading.Thread(target=worker, name="transume-storage-connect", daemon=True).start()
            chooser = StorageLocationChooser(self, selected, cancelled)
            self._storage_chooser = chooser
            chooser.present()

        def _use_external_location(self, location: StorageLocation, callback: Callable[[Path], None], chooser: StorageLocationChooser | None, request: int) -> None:
            if chooser is not self._storage_chooser or request != self._storage_request:
                return
            try:
                session = self.storage_manager.register_existing_local_folder(location.root)
                session.effective_location = session.location
                self._set_model_location(session.location)
                self._storage_session = session
                if self._storage_chooser is chooser:
                    chooser.destroy()
                    self._storage_chooser = None
                callback(Path(session.location.root))
            except (OSError, ValueError) as error:
                if chooser is self._storage_chooser:
                    chooser.set_failure(str(error))

        def _mounted_location(self, chooser: StorageLocationChooser | None, request: int, session: Any, location: StorageLocation, callback: Callable[[Path], None]) -> bool:
            if chooser is not self._storage_chooser or request != self._storage_request:
                self._unmount_stale(session)
                return GLib.SOURCE_REMOVE
            try:
                self._set_model_location(location)
                session.effective_location = location
                self._storage_session = session
                chooser.destroy()
                self._storage_chooser = None
                callback(Path(location.root))
            except FileNotFoundError:
                self._storage_failed(chooser, request, session, _("Requested storage folder was not found."))
            except PermissionError:
                self._storage_failed(chooser, request, session, _("Storage folder is not accessible."))
            except (OSError, StorageError, ValueError) as error:
                self._storage_failed(chooser, request, session, str(error))
            return GLib.SOURCE_REMOVE

        def _unmount_stale(self, session: Any) -> None:
            if session.state is ConnectionState.MOUNTED:
                threading.Thread(target=lambda: self.storage_manager.unmount(session), name="transume-stale-unmount", daemon=True).start()

        def _storage_failed(self, chooser: StorageLocationChooser | None, request: int, session: Any, detail: str) -> bool:
            if session.state is ConnectionState.MOUNTED:
                self._unmount_stale(session)
            if chooser is self._storage_chooser and request == self._storage_request:
                chooser.set_failure(detail)
            return GLib.SOURCE_REMOVE

        def _set_model_location(self, location: StorageLocation) -> None:
            setter = getattr(self.model, "set_storage_location", None)
            if callable(setter): setter(location)
            else: self.model.set_repository(Path(location.root))

        def choose_image(self, callback: Callable[[ImageCandidate], None]) -> None:
            previous = self.stack.get_visible_child_name() or "restore"

            def selected(image: ImageCandidate) -> None:
                callback(image)
                self.navigate(previous)

            browser = ImageBrowserPage(
                self.model,
                self.choose_storage_location,
                selected,
                lambda: self.navigate(previous),
                self.images_page.image_controls,
            )
            old = self.stack.get_child_by_name("image-browser")
            if old is not None:
                self.stack.remove(old)
            self.stack.add_named(browser, "image-browser")
            self.stack.set_visible_child_name("image-browser")

        def _restore_image(self, image: ImageCandidate) -> None:
            restore = self.route_editors[1]
            restore._set_item("source", image)
            self.navigate("restore")

        def open_restore_mapping(self, image: ImageCandidate, callback: Callable[[list[Any]], None]) -> None:
            previous = self.stack.get_visible_child_name() or "restore"
            page: RestoreMappingPage
            def choose(index: int) -> None:
                self.open_picker("devices", _("Choose destination {index}").format(index=index + 1),
                                 lambda item: (page.set_target(index, item), self.navigate("restore-mapping")))
            def complete() -> None:
                if all(page.targets):
                    callback([value for value in page.targets if value is not None])
                    self.navigate(previous)
            page = RestoreMappingPage(image, choose, complete, lambda: self.navigate(previous))
            old = self.stack.get_child_by_name("restore-mapping")
            if old is not None: self.stack.remove(old)
            self.stack.add_named(page, "restore-mapping")
            self.stack.set_visible_child_name("restore-mapping")


        def open_review(self, operation: Any, selection: dict[str, Any] | None = None,
                         secret_prompt: Callable[[Callable[[SecretValue], None]], None] | None = None) -> None:
            try:
                context = None
                if isinstance(operation, JobDraft):
                    spec = build_draft(operation)
                    label = operation.operation
                    context = operation.image_context
                    display = {"source": self._selection_name(operation.source),
                               "destination": ", ".join(self._selection_name(value) for value in operation.destinations)}
                elif isinstance(operation, str):
                    spec = build_draft(operation, selection or {})
                    label = operation
                    display = {
                        "source": self._selection_name((selection or {}).get("source")),
                        "destination": self._selection_name((selection or {}).get("destination")),
                    }
                else:
                    spec = operation
                    label = spec.operation.value.replace("-", " ")
                    display = selection or {}
                report = PreflightService().check(spec, image_context=context)
                report.require_ok()
                validation = run_spec(spec, dry_run=True)
                serial = (", ".join((value.serial or value.wwn or value.path)[-4:]
                                    for value in spec.destinations) if spec.destinations else None)
                def start() -> None:
                    # Recheck selected image evidence after the user has read Review.
                    try:
                        PreflightService().check(spec, image_context=context).require_ok()
                        if secret_prompt is None:
                            if ((spec.operation.value in {"savedisk", "saveparts"} and spec.options.get("encrypt") is True)
                                    or (spec.operation.value in {"restoredisk", "restoreparts"} and spec.options.get("encrypted") is True)):
                                self._prompt_encryption_secret(lambda secret: self.start_job(label, spec, secret), backup=spec.options.get("encrypt") is True)
                            else:
                                self.start_job(label, spec)
                        else:
                            secret_prompt(lambda secret: self.start_job(label, spec, secret))
                    except (OSError, ValueError) as error:
                        present_message(
                            self, _("Preflight changed"), str(error),
                            icon_name="dialog-warning-symbolic",
                        )

                review = ReviewPage(label, display, validation.detail, serial, spec.risk, start, spec,
                                    warnings=tuple(issue.message for issue in report.issues
                                                   if issue.severity is Severity.WARNING))
            except (OSError, RuntimeError, ValueError) as error:
                present_message(
                    self, _("Operation is not ready"), str(error),
                    icon_name="dialog-warning-symbolic",
                )
                return
            old = self.stack.get_child_by_name("review")
            if old is not None:
                self.stack.remove(old)
            self.stack.add_named(review, "review")
            self.stack.set_visible_child_name("review")

        def _prompt_encryption_secret(self, start: Callable[[SecretValue], None], *, backup: bool) -> None:
            """Collect the backup key only after review; it never enters JobDraft."""
            title = _("Encrypt backup") if backup else _("Restore encrypted image")
            detail = (_("Set the eCryptfs passphrase for this backup.") if backup
                      else _("Enter the eCryptfs passphrase required to restore this image."))
            dialog, content = dialog_shell(
                self, title, detail, width=500, icon_name="channel-secure-symbolic",
            )
            fields = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10,
                             css_classes=["dialog-form"])
            passphrase = Gtk.PasswordEntry(placeholder_text=_("Passphrase"))
            set_accessible_label(passphrase, _("Backup encryption passphrase") if backup else _("Encrypted image passphrase"))
            fields.append(passphrase)
            confirm = Gtk.PasswordEntry(placeholder_text=_("Confirm passphrase")) if backup else None
            if confirm is not None:
                set_accessible_label(confirm, _("Confirm backup encryption passphrase"))
                fields.append(confirm)
            content.append(fields)
            actions = dialog_actions(content)
            cancel = Gtk.Button(label=_("Cancel"))
            start_button = Gtk.Button(label=_("Start"), css_classes=["suggested-action"])
            actions.append(cancel)
            actions.append(start_button)

            def respond(accepted: bool) -> None:
                entered, repeated = passphrase.get_text(), confirm.get_text() if confirm is not None else ""
                passphrase.set_text("")
                if confirm is not None:
                    confirm.set_text("")
                dialog.destroy()
                try:
                    if not accepted:
                        return
                    if backup and entered != repeated:
                        raise ValueError(_("Passphrases do not match"))
                    start(SecretValue.from_text(entered))
                except ValueError as error:
                    present_message(
                        self, _("Operation is not ready"), str(error),
                        icon_name="dialog-warning-symbolic",
                    )
                finally:
                    entered = repeated = ""
            cancel.connect("clicked", lambda _button: respond(False))
            start_button.connect("clicked", lambda _button: respond(True))
            passphrase.connect("activate", lambda _entry: start_button.emit("clicked"))
            if confirm is not None:
                confirm.connect("activate", lambda _entry: start_button.emit("clicked"))
            dialog.present()

        @staticmethod
        def _selection_name(item: Any) -> str:
            if isinstance(item, Path):
                return str(item)
            return str(getattr(item, "name", None) or getattr(item, "path", None) or item)

        def start_job(self, operation: str, spec: Any, secret: SecretValue | None = None) -> None:
            self.navigate("activity")
            cancel = threading.Event()
            self._job_cancel = cancel
            repository = getattr(spec, "repository", None)
            job_storage = next((session for session in self.storage_manager.sessions
                                if session.state is ConnectionState.MOUNTED
                                and isinstance(repository, str)
                                and _repository_contains(
                                    (session.effective_location or session.location).root,
                                    repository,
                                )), None)
            self._job_storage_session = job_storage
            activity_start = getattr(self.model, "start_activity", None)
            job_id = activity_start(operation, spec) if callable(activity_start) else None
            log = LogStore(job_id, root=self.model.log_dir) if job_id is not None else None
            self.activity_page.begin(operation, cancel.set)
            if job_id is not None:
                record = next((item for item in self.model.list_activity() if item.job_id == job_id), None)
                self.activity_page.set_current_record(record)

            def event(message: dict[str, Any]) -> None:
                if log is not None:
                    log.append(message)
                GLib.idle_add(self.activity_page.handle_event, message)

            def worker() -> None:
                status = "failed"
                detail = "Operation failed"
                exit_code = verification = runner_cleanup = None
                try:
                    result = run_spec(spec, dry_run=False, on_event=event, cancel_event=cancel,
                                      secret=secret)
                    status, detail = result.status, result.detail
                    exit_code = result.exit_code
                    verification = result.verification
                    runner_cleanup = result.cleanup
                except AuthorizationError:
                    status = "cancelled"
                    detail = _("Operation cancelled")
                except Exception as error:
                    detail = str(error)
                finally:
                    cleanup = _merge_cleanup(runner_cleanup, "not-needed")
                    if log is not None:
                        log.close()
                    GLib.idle_add(
                        self._finish_job, job_id, status, detail, spec, exit_code,
                        verification, cleanup,
                    )
                    GLib.idle_add(self._job_finished)

            threading.Thread(target=worker, name="transume-job", daemon=True).start()

        def _finish_job(self, job_id: str | None, status: str, detail: str, spec: Any,
                         exit_code: int | None, verification: str | None,
                         cleanup: str | None) -> bool:
            if job_id is not None:
                finish = getattr(self.model, "finish_activity", None)
                if callable(finish):
                    finish(job_id, status, detail, exit_code=exit_code, verification=verification,
                           cleanup=cleanup)
            if spec.operation.value == "check-image" and status == "ok":
                candidate = next((item for item in self.model.list_images()
                                  if item.name == getattr(spec, "image_name", None)), None)
                # The selected image is stable by location and relative id; the catalog
                # refuses a mark if it disappeared before completion.
                if candidate is not None:
                    marker = getattr(self.model, "mark_verified", None)
                    if callable(marker):
                        marker(candidate)
                self.images_page._render()
            self.activity_page.finish(status, detail, risk=getattr(spec, "risk", ""))
            if cleanup == "failed":
                self._show_mount_recovery()
            return GLib.SOURCE_REMOVE

        def _show_mount_recovery(self) -> None:
            session = self._storage_session
            if session is None or session.ownership is not MountOwnership.TRANSUME:
                return
            present_message(
                self, _("Storage cleanup failed"),
                _("The mounted storage remains available. Retry unmount before removing media."),
                primary_label=_("Retry unmount"),
                on_primary=lambda: self.retry_storage_unmount(session),
                icon_name="dialog-warning-symbolic",
            )

        def retry_storage_unmount(self, session: Any | None = None) -> None:
            session = session or self._storage_session
            if session is None or session.ownership is not MountOwnership.TRANSUME:
                return
            def worker() -> None:
                try:
                    self.storage_manager.unmount(session)
                    if self._storage_session is session:
                        self._storage_session = None
                        clear = getattr(self.model, "clear_current_location", None)
                        if callable(clear):
                            GLib.idle_add(clear)
                except StorageError:
                    GLib.idle_add(self._show_mount_recovery)
            threading.Thread(target=worker, name="transume-storage-retry", daemon=True).start()

else:
    class MainWindow:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            require_gtk()


def _repository_contains(root: str, repository: str) -> bool:
    try:
        Path(repository).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False


def _merge_cleanup(runner: str | None, mount: str) -> str:
    values = {runner, mount}
    if "failed" in values:
        return "failed"
    if "complete" in values:
        return "complete"
    return "not-needed"
