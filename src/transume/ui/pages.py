"""Primary Transume workspace pages."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
from importlib import metadata
import os
import shutil
import sys
import threading
import time
from typing import Any, Callable, Iterable

from .. import __version__
from .components import (ImageCard, SelectionCard, dialog_actions, dialog_shell,
                         model_value, style_dropdown)
from .gtk import Gio, GLib, Gtk, Pango, require_gtk, set_accessible_label
from ..images import ImageCandidate, ImageStatus, ImageType
from ..draft import image_fingerprint
from ..image_explorer import ExplorerRequest, explorer_support_reason
from uuid import uuid4
from ..controller import build_image_action
from ..draft import JobDraft
from ..progress import elapsed_and_eta
from ..storage import StorageError, StorageKind, StorageLocation, scan_ssh_host_keys
from ..i18n import _


def _smb_credentials(domain: str, username: str, password: str) -> dict[str, str]:
    if username and not password:
        raise ValueError(_("SMB password is required"))
    if (domain or password) and not username:
        raise ValueError(_("SMB username is required"))
    return {key: value for key, value in (
        ("domain", domain), ("username", username), ("password", password)
    ) if value}


def _call_model(model: Any, method: str) -> tuple[list[Any], str | None]:
    """Read an optional model API, retaining a presentable failure."""
    callback = getattr(model, method, None) if model is not None else None
    if not callable(callback):
        return [], _("{method} is unavailable").format(method=method.replace("_", " "))
    try:
        result = callback()
        return list(result) if result is not None else [], None
    except Exception as error:
        return [], _("Could not load {method}: {error}").format(method=method.replace("_", " "), error=str(error)[:240])


if Gtk is not None:
    def page_heading(title: str, subtitle: str) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        heading = Gtk.Label(label=title, xalign=0)
        heading.add_css_class("page-title")
        box.append(heading)
        description = Gtk.Label(label=subtitle, xalign=0, wrap=True)
        description.add_css_class("muted")
        box.append(description)
        return box


    class StorageLocationChooser(Gtk.Dialog):
        """Collect one ephemeral storage authorization request."""

        __gtype_name__ = "TransumeStorageLocationChooser"

        def __init__(self, parent: Gtk.Window, on_location: Callable[[StorageLocation, dict[str, str]], None],
                     on_cancel: Callable[[], None]) -> None:
            super().__init__(title=_("Choose storage location"), transient_for=parent, modal=True)
            self.on_location, self.on_cancel = on_location, on_cancel
            self._connecting = False
            self._folder_chooser: Gtk.FileChooserNative | None = None
            self._identity_chooser: Gtk.FileChooserNative | None = None
            self.set_default_size(540, 1)
            self.set_resizable(True)
            self.connect("close-request", self._close_request)
            body = self.get_content_area()
            body.set_spacing(18)
            body.set_margin_top(20); body.set_margin_bottom(16)
            body.set_margin_start(20); body.set_margin_end(20)
            body.append(page_heading(
                _("Storage location"),
                _("Choose where Transume should read or store Clonezilla images."),
            ))
            form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            form.add_css_class("info-card")
            form.append(Gtk.Label(label=_("LOCATION TYPE"), xalign=0, css_classes=["setting-label"]))
            self.ssh_available = shutil.which("sshfs", path="/usr/sbin:/usr/bin:/sbin:/bin") is not None
            self.kind = Gtk.DropDown.new_from_strings([_("Local folder"), "SMB/CIFS", "NFS", "SSH/SFTP"])
            self.kind.add_css_class("storage-kind-dropdown")
            style_dropdown(self.kind, icons=("folder-symbolic", "network-server-symbolic",
                                             "folder-remote-symbolic", "network-wired-symbolic"))
            set_accessible_label(self.kind, _("Storage type"))
            self.kind.connect("notify::selected", self._kind_changed)
            form.append(self.kind)
            self.stack = Gtk.Stack(vhomogeneous=False, hhomogeneous=False)
            self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
            form.append(self.stack)
            self.message = Gtk.Label(xalign=0, wrap=True, css_classes=["muted"])
            self.message.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            self.message.set_max_width_chars(58)
            form.append(self.message)
            self._local_page(parent)
            self._network_page("smb")
            self._network_page("nfs")
            self._network_page("ssh")
            body.append(form)
            actions = Gtk.Box(spacing=8, halign=Gtk.Align.END)
            actions.add_css_class("dialog-actions")
            self.cancel_button = Gtk.Button(label=_("Cancel"))
            self.cancel_button.connect("clicked", lambda _button: self._cancel())
            actions.append(self.cancel_button)
            self.connect_button = Gtk.Button(label=_("Connect"))
            self.connect_button.add_css_class("suggested-action")
            set_accessible_label(self.connect_button, _("Connect storage location"))
            self.connect_button.connect("clicked", lambda _button: self.connect_location())
            actions.append(self.connect_button)
            body.append(actions)
            self._kind_changed(self.kind, None)

        @staticmethod
        def _entry(label: str, *, secret: bool = False) -> Gtk.Entry:
            entry = Gtk.Entry(visibility=not secret)
            entry.set_max_length(128)
            set_accessible_label(entry, label)
            return entry

        def _local_page(self, parent: Gtk.Window) -> None:
            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.local_path = None
            self.local_button = Gtk.Button(label=_("Choose folder"))
            set_accessible_label(self.local_button, _("Choose local storage folder"))
            def choose(_button: Gtk.Button) -> None:
                if self._folder_chooser is not None:
                    self._folder_chooser.show()
                    return
                native = Gtk.FileChooserNative(
                    title=_("Choose storage folder"), transient_for=self,
                    action=Gtk.FileChooserAction.SELECT_FOLDER,
                    accept_label=_("Choose"), cancel_label=_("Cancel"),
                )
                self._folder_chooser = native
                def response(dialog: Gtk.FileChooserNative, response_id: int) -> None:
                    if response_id == Gtk.ResponseType.ACCEPT and (item := dialog.get_file()) and item.get_path():
                        self.local_path = Path(item.get_path()).resolve(strict=False)
                        self.local_button.set_label(self.local_path.name or str(self.local_path))
                        self.message.set_label("")
                    dialog.destroy()
                    self._folder_chooser = None
                native.connect("response", response)
                native.show()
            self.local_button.connect("clicked", choose)
            page.append(self.local_button)
            self.stack.add_named(page, "local")

        def _network_page(self, name: str) -> None:
            page = Gtk.Grid(row_spacing=8, column_spacing=10)
            fields: dict[str, Gtk.Entry] = {}
            names = (("host", _("Host")), ("share", _("Share")), ("subfolder", _("Optional subfolder")),
                      ("domain", _("Domain (optional)")), ("username", _("Username")), ("password", _("Password"))) if name == "smb" else (("host", _("Host")), ("export", _("Export path"))) if name == "nfs" else (("host", _("Host")), ("port", _("Port (optional)")), ("username", _("Username")), ("folder", _("Absolute remote folder")))
            for row, (key, label) in enumerate(names):
                field = self._entry(f"{name.upper()} {label}", secret=key == "password")
                field.set_hexpand(True)
                fields[key] = field
                field_label = Gtk.Label(label=label, xalign=0, wrap=True,
                                        max_width_chars=18)
                page.attach(field_label, 0, row, 1, 1)
                page.attach(field, 1, row, 1, 1)
            if name == "ssh":
                row = len(names)
                auth_label = Gtk.Label(label=_("Authentication"), xalign=0)
                self.ssh_auth = Gtk.DropDown.new_from_strings([
                    _("SSH agent"), _("Private key"), _("Password"),
                ])
                style_dropdown(self.ssh_auth)
                self.ssh_auth.set_selected(0 if os.environ.get("SSH_AUTH_SOCK") else 1)
                self.ssh_auth.connect("notify::selected", self._ssh_auth_changed)
                page.attach(auth_label, 0, row, 1, 1)
                page.attach(self.ssh_auth, 1, row, 1, 1)

                self.ssh_password_label = Gtk.Label(label=_("Password"), xalign=0)
                password = self._entry("SSH Password", secret=True)
                password.set_hexpand(True)
                fields["password"] = password
                page.attach(self.ssh_password_label, 0, row + 1, 1, 1)
                page.attach(password, 1, row + 1, 1, 1)

                self.ssh_identity_label = Gtk.Label(label=_("Private key"), xalign=0)
                self.ssh_identity_path: Path | None = None
                self.ssh_identity_button = Gtk.Button(label=_("Choose file"))
                self.ssh_identity_button.connect("clicked", self._choose_ssh_identity)
                page.attach(self.ssh_identity_label, 0, row + 2, 1, 1)
                page.attach(self.ssh_identity_button, 1, row + 2, 1, 1)
            setattr(self, f"{name}_fields", fields)
            self.stack.add_named(page, name)
            if name == "ssh":
                self._ssh_auth_changed(self.ssh_auth, None)

        def _choose_ssh_identity(self, _button: Gtk.Button) -> None:
            if self._identity_chooser is not None:
                self._identity_chooser.show()
                return
            native = Gtk.FileChooserNative(
                title=_("Choose file"), transient_for=self,
                action=Gtk.FileChooserAction.OPEN,
                accept_label=_("Choose"), cancel_label=_("Cancel"),
            )
            self._identity_chooser = native
            def response(dialog: Gtk.FileChooserNative, response_id: int) -> None:
                if response_id == Gtk.ResponseType.ACCEPT and (item := dialog.get_file()) and item.get_path():
                    self.ssh_identity_path = Path(item.get_path()).resolve(strict=False)
                    self.ssh_identity_button.set_label(self.ssh_identity_path.name)
                    self.ssh_identity_button.set_tooltip_text(str(self.ssh_identity_path))
                dialog.destroy()
                self._identity_chooser = None
            native.connect("response", response)
            native.show()

        def _ssh_auth_changed(self, control: Gtk.DropDown, _detail: Any) -> None:
            method = control.get_selected()
            self.ssh_password_label.set_visible(method == 2)
            self.ssh_fields["password"].set_visible(method == 2)
            self.ssh_identity_label.set_visible(method == 1)
            self.ssh_identity_button.set_visible(method == 1)

        def _kind_changed(self, control: Gtk.DropDown, _detail: Any) -> None:
            name = ("local", "smb", "nfs", "ssh")[control.get_selected()]
            self.stack.set_visible_child_name(name)
            if name == "ssh":
                self.message.set_label(_("SSH/SFTP is unavailable because sshfs is not installed.") if not self.ssh_available else _("New SSH hosts are trusted on first use. Changed host keys are rejected."))
                self.connect_button.set_sensitive(self.ssh_available)
            else:
                self.message.set_label("")
                self.connect_button.set_sensitive(True)

        def _cancel(self) -> None:
            self.on_cancel()
            self.destroy()

        def _close_request(self, _dialog: Gtk.Dialog) -> bool:
            self._cancel()
            return True

        def connect_location(self) -> None:
            try:
                selected = self.kind.get_selected()
                if selected == 0:
                    if self.local_path is None:
                        raise ValueError(_("Choose a local folder first"))
                    location = StorageLocation(StorageKind.LOCAL_FOLDER, str(self.local_path))
                    credentials: dict[str, str] = {}
                elif selected == 1:
                    fields = self.smb_fields
                    subfolder = fields["subfolder"].get_text().strip() or "/"
                    if not subfolder.startswith("/"): subfolder = "/" + subfolder
                    location = StorageLocation(StorageKind.SMB, "/pending", host=fields["host"].get_text().strip(), share=fields["share"].get_text().strip(), endpoint=subfolder)
                    credentials = _smb_credentials(
                        fields["domain"].get_text().strip(),
                        fields["username"].get_text().strip(),
                        fields["password"].get_text(),
                    )
                elif selected == 2:
                    fields = self.nfs_fields
                    location = StorageLocation(StorageKind.NFS, "/pending", host=fields["host"].get_text().strip(), endpoint=fields["export"].get_text().strip())
                    credentials = {}
                else:
                    if not self.ssh_available:
                        raise ValueError(_("SSH/SFTP is unavailable because sshfs is not installed"))
                    fields = self.ssh_fields
                    port_text = fields["port"].get_text().strip()
                    port = int(port_text) if port_text else None
                    location = StorageLocation(StorageKind.SSH, "/pending", host=fields["host"].get_text().strip(),
                                               port=port, username=fields["username"].get_text().strip(),
                                               endpoint=fields["folder"].get_text().strip())
                    method = ("agent", "private-key", "password")[self.ssh_auth.get_selected()]
                    credentials = {"auth_method": method}
                    if method == "password":
                        password = fields["password"].get_text()
                        if not password:
                            raise ValueError(_("SSH password is required"))
                        credentials["password"] = password
                    elif method == "private-key":
                        if self.ssh_identity_path is None:
                            raise ValueError(_("Choose file"))
                        credentials["identity_file"] = str(self.ssh_identity_path)
                    else:
                        agent_socket = os.environ.get("SSH_AUTH_SOCK", "")
                        if not agent_socket:
                            raise ValueError(_("SSH agent is unavailable"))
                        credentials["agent_socket"] = agent_socket
                    self._scan_ssh_key(location, credentials)
                    return
            except ValueError as error:
                self.message.set_label(str(error))
                return
            self.message.set_label(_("Connecting...") if selected else "")
            self.connect_button.set_sensitive(False)
            self._connecting = True
            self.cancel_button.set_label(_("Cancel connection"))
            if selected == 1:
                # Credentials now exist only in the one-shot request dictionary.
                self.smb_fields["password"].set_text("")
            elif selected == 3:
                self.ssh_fields["password"].set_text("")
            self.on_location(location, credentials)

        def _scan_ssh_key(self, location: StorageLocation, credentials: dict[str, str]) -> None:
            """Pin a first-use host key automatically before sending credentials."""
            self.message.set_label(_("Scanning SSH host key..."))
            self.connect_button.set_sensitive(False)
            def worker() -> None:
                try:
                    keys = scan_ssh_host_keys(location.host or "", location.port)
                except Exception as error:
                    GLib.idle_add(self._ssh_scan_failed, str(error))
                    return
                preference = {"ssh-ed25519": 0, "ecdsa-sha2-nistp256": 1, "rsa-sha2-512": 2,
                              "rsa-sha2-256": 3, "ssh-rsa": 4}
                key = min(keys, key=lambda value: preference.get(value.split()[1], 99))
                GLib.idle_add(self._connect_scanned_ssh, location, credentials, key)
            threading.Thread(target=worker, name="transume-ssh-keyscan", daemon=True).start()

        def _ssh_scan_failed(self, detail: str) -> None:
            self.message.set_label(_("SSH host-key scan failed: {detail}").format(detail=detail))
            self.connect_button.set_sensitive(True)

        def _connect_scanned_ssh(self, location: StorageLocation,
                                 credentials: dict[str, str], key: str) -> bool:
            credentials["host_key"] = key
            self.ssh_fields["password"].set_text("")
            self.message.set_label(_("Connecting..."))
            self._connecting = True
            self.cancel_button.set_label(_("Cancel connection"))
            self.on_location(location, credentials)
            return GLib.SOURCE_REMOVE

        def set_failure(self, detail: str) -> None:
            self._connecting = False
            self.connect_button.set_sensitive(True)
            self.cancel_button.set_label(_("Cancel"))
            self.message.set_label(_("Connection failed: {detail}. Correct the details and retry.").format(detail=detail))


    class HomePage(Gtk.ScrolledWindow):
        __gtype_name__ = "TransumeHomePage"

        def __init__(self, navigate: Callable[[str], None]) -> None:
            super().__init__(hscrollbar_policy=Gtk.PolicyType.NEVER)
            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
            content.add_css_class("page")
            content.append(Gtk.Label(label=_("Choose an action"), xalign=0,
                                     css_classes=["page-title"]))
            tiles = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE,
                                column_spacing=16, row_spacing=16,
                                min_children_per_line=1, max_children_per_line=2)
            self.action_buttons: dict[str, Gtk.Button] = {}
            for name, title, description, icon_name in (
                ("backup", _("Backup"), _("Create a disk or partition image"), "document-save-symbolic"),
                ("restore", _("Restoration"), _("Restore an image to a device"), "document-revert-symbolic"),
                ("clone", _("Clone"), _("Copy a disk or partition directly"), "edit-copy-symbolic"),
                ("images", _("Images"), _("Browse and manage saved images"), "folder-pictures-symbolic"),
                ("activity", _("Activity"), _("View operation history"), "view-list-symbolic"),
            ):
                button = Gtk.Button()
                button.add_css_class("action-card")
                button.set_hexpand(True)
                body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
                icon = Gtk.Image.new_from_icon_name(icon_name)
                icon.set_pixel_size(32)
                icon.set_halign(Gtk.Align.START)
                body.append(icon)
                body.append(Gtk.Label(label=title, xalign=0, css_classes=["card-title"]))
                body.append(Gtk.Label(label=description, xalign=0, wrap=True,
                                      css_classes=["muted"]))
                button.set_child(body)
                set_accessible_label(button, title)
                button.connect("clicked", lambda _button, target=name: navigate(target))
                tiles.insert(button, -1)
                self.action_buttons[name] = button
            content.append(tiles)
            self.set_child(content)
            self.tiles = tiles

    class AboutPage(Gtk.ScrolledWindow):
        __gtype_name__ = "TransumeAboutPage"

        def __init__(self, _navigate: Callable[[str], None], model: Any = None) -> None:
            super().__init__(hscrollbar_policy=Gtk.PolicyType.NEVER)
            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
            content.add_css_class("page")
            content.append(Gtk.Label(
                label=_("About Transume"), xalign=0,
                css_classes=["page-title"],
            ))

            try:
                app_version = metadata.version("transume")
            except metadata.PackageNotFoundError:
                app_version = __version__
            runtime = getattr(model, "capabilities", None)
            clonezilla_version = getattr(runtime, "version", None) or _("Unavailable")
            gtk_version = ".".join(str(value) for value in (
                Gtk.get_major_version(), Gtk.get_minor_version(), Gtk.get_micro_version(),
            ))
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

            def badge(label: str, style: str = "") -> Gtk.Label:
                result = Gtk.Label(label=label, css_classes=["about-badge"])
                result.set_valign(Gtk.Align.CENTER)
                if style:
                    result.add_css_class(style)
                return result

            def section(title: str) -> Gtk.Box:
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
                box.add_css_class("info-card")
                box.append(Gtk.Label(label=title, xalign=0, css_classes=["card-title"]))
                return box

            def feature(icon_name: str, title: str, description: str) -> Gtk.Box:
                row = Gtk.Box(spacing=12)
                row.add_css_class("about-feature")
                icon = Gtk.Image.new_from_icon_name(icon_name)
                icon.set_pixel_size(20)
                icon.set_valign(Gtk.Align.START)
                row.append(icon)
                text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                text.append(Gtk.Label(label=title, xalign=0, css_classes=["setting-value"]))
                text.append(Gtk.Label(label=description, xalign=0, wrap=True, css_classes=["muted"]))
                row.append(text)
                return row

            def readiness_row(title: str, detail: str, ready: bool) -> Gtk.Box:
                row = Gtk.Box(spacing=10)
                row.add_css_class("about-readiness")
                text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
                text.append(Gtk.Label(label=title, xalign=0, css_classes=["setting-value"]))
                text.append(Gtk.Label(label=detail, xalign=0, wrap=True, css_classes=["muted"]))
                row.append(text)
                row.append(badge(_("Ready") if ready else _("Unavailable"), "success" if ready else "warning"))
                return row

            introduction = Gtk.Box(spacing=18)
            introduction.add_css_class("info-card")
            logo_path = Path(__file__).resolve().parents[3] / "data" / "pixmaps" / "transume-logo.svg"
            if not logo_path.exists():
                logo_path = Path("/usr/share/pixmaps/transume-logo.svg")
            logo = Gtk.Image.new_from_file(str(logo_path))
            logo.set_size_request(128, 128)
            logo.set_valign(Gtk.Align.START)
            introduction.append(logo)
            intro_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
            intro_text.append(Gtk.Label(
                label=_("Transume {version}").format(version=app_version),
                xalign=0, wrap=True, css_classes=["action-title"],
            ))
            intro_text.append(Gtk.Label(
                label=_("The name Transume comes from a historical English verb used in "
                       "the world of documents. It described making an official copy or "
                       "extract, and attesting that a copy matched its source. Transume "
                       "brings the same idea to disks: preserving a system's structure "
                       "and contents so they can be checked, restored, or reproduced "
                       "on another drive."),
                xalign=0, wrap=True, css_classes=["muted"],
            ))
            introduction.append(intro_text)
            content.append(introduction)

            self.columns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
            left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, hexpand=True)
            right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, hexpand=True)
            widths = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)
            widths.add_widget(left)
            widths.add_widget(right)

            capabilities = section(_("Capabilities"))
            capability_rows = (
                ("document-save-symbolic", _("Create images"), _("Back up complete disks or selected partitions, with verification and optional native encryption.")),
                ("document-revert-symbolic", _("Restore images"), _("Restore supported full-disk and partition images with explicit destination warnings.")),
                ("edit-copy-symbolic", _("Clone storage"), _("Copy a disk or partition directly to an equal or larger local destination.")),
                ("folder-pictures-symbolic", _("Manage images"), _("Discover, inspect, verify, rename, delete, and explore supported Partclone images read-only.")),
                ("folder-open-symbolic", _("Image Explorer"), _("Read-only Partclone file access")),
                ("folder-remote-symbolic", _("Use different storage"), _("Work with local, removable, SMB, NFS, and SSH storage locations.")),
            )
            for icon_name, title, description in capability_rows:
                capabilities.append(feature(icon_name, title, description))
            left.append(capabilities)

            readiness = section(_("System readiness"))
            core_ready = bool(runtime and {"savedisk", "saveparts", "restoredisk", "restoreparts", "clone-disk", "clone-part"} <= runtime.modes)
            encryption_ready = bool(runtime and runtime.supports("ecryptfs"))
            network_ready = bool(runtime and runtime.supports("sshfs"))
            explorer_ready = bool(runtime and all(runtime.supports(name) for name in ("partclone-nbd", "nbdkit", "nbd-client", "setfacl", "blockdev")))
            readiness.append(readiness_row(_("Core imaging"), _("Disk and partition backup, restore, clone, and verification"), core_ready))
            readiness.append(readiness_row(_("Encrypted backup"), _("Clonezilla native eCryptfs workflow"), encryption_ready))
            readiness.append(readiness_row(_("Network storage"), _("SMB, NFS, and SSH repositories"), network_ready))
            readiness.append(readiness_row(_("Image Explorer"), _("Read-only Partclone file access"), explorer_ready))
            versions = Gtk.Grid(column_spacing=14, row_spacing=6)
            versions.add_css_class("about-versions")
            for row, (name, value) in enumerate((
                ("Clonezilla", clonezilla_version),
                (_("Partclone"), ((runtime.partclone_version or _("Available")) if runtime and runtime.supports("partclone") else _("Unavailable"))),
                (_("Python"), python_version),
                ("GTK", gtk_version),
            )):
                versions.attach(Gtk.Label(label=name, xalign=0, css_classes=["muted"]), 0, row, 1, 1)
                versions.attach(Gtk.Label(label=value, xalign=1, css_classes=["setting-value"]), 1, row, 1, 1)
            readiness.append(versions)
            right.append(readiness)

            project = section(_("Project"))
            project.append(Gtk.Label(
                label=_("Copyright (C) 2026 MiniOS Linux.\n"
                       "Powered by Clonezilla and Partclone.\n"
                       "Licensed under GNU GPL 3.0 or later."),
                xalign=0, wrap=True,
            ))
            actions = Gtk.Box(spacing=8)
            homepage = Gtk.LinkButton.new_with_label("https://minios.dev/", _("Project website"))
            actions.append(homepage)
            project.append(actions)
            right.append(project)

            self.columns.append(left)
            self.columns.append(right)
            content.append(self.columns)
            self.set_child(content)

        def set_compact(self, compact: bool) -> None:
            self.columns.set_orientation(
                Gtk.Orientation.VERTICAL if compact else Gtk.Orientation.HORIZONTAL
            )


    class RouteEditorPage(Gtk.Box):
        __gtype_name__ = "TransumeRouteEditorPage"

        def __init__(
            self,
            operation: str,
            model: Any,
            open_picker: Callable[[str, str, Callable[[Any], None]], None],
            choose_repository: Callable[[Callable[[Path], None]], None],
            choose_image: Callable[[Callable[[Any], None]], None],
            review: Callable[[str, dict[str, Any]], None],
            shared_card_widths: Gtk.SizeGroup | None = None,
            shared_context_widths: Gtk.SizeGroup | None = None,
            on_back: Callable[[], None] | None = None,
            open_restore_mapping: Callable[[ImageCandidate, Callable[[list[Any]], None]], None] | None = None,
        ) -> None:
            super().__init__(orientation=Gtk.Orientation.VERTICAL)
            self.operation = operation
            # One draft is the source of truth for every visible control.
            self.draft = JobDraft(operation)
            self.selection: dict[str, Any] = {}
            self.settings: dict[str, str | bool | int] = {}
            self.metric_values: dict[str, Gtk.Label] = {}
            self.review_callback = review
            self._on_back = on_back
            self._open_restore_mapping = open_restore_mapping
            self._open_picker = open_picker
            scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
            scroll.set_hexpand(True)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
            body.add_css_class("page")
            body.set_vexpand(True)
            titles = {
                "backup": _("Create a backup"),
                "restore": _("Restore from an image"),
                "clone": _("Clone a drive"),
            }
            descriptions = {
                "backup": _("Select source, operation and destination to create a disk image."),
                "restore": _("Select an image and inspect the drive that will be overwritten."),
                "clone": _("Select source and destination for a direct disk copy."),
            }
            body.append(page_heading(titles[operation], descriptions[operation]))

            workspace = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
            workspace.add_css_class("editor-workspace")
            route_column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
            route_column.set_hexpand(True)
            route = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            route.add_css_class("route")
            route.set_valign(Gtk.Align.START)
            self.route = route
            source_is_image = operation == "restore"
            source_role = _("Image") if source_is_image else _("Source")
            source_prompt = _("No image selected") if source_is_image else _("Choose a drive")

            def choose_source() -> None:
                if source_is_image:
                    choose_image(lambda item: self._set_item("source", item))
                else:
                    open_picker(
                        "devices", _("Choose source"),
                        lambda item: self._set_item("source", item),
                    )

            self.source = SelectionCard(
                source_role, source_prompt, "drive-harddisk-symbolic", choose_source,
                self._drop_source if source_is_image else None, step=1,
                choose_label=_("Browse images") if source_is_image else _("Choose"),
            )
            route.append(self.source)
            def connector() -> tuple[Gtk.Box, Gtk.Image]:
                box = Gtk.Box(spacing=0)
                box.add_css_class("route-connector")
                box.set_valign(Gtk.Align.CENTER)
                image = Gtk.Image.new_from_icon_name("go-next-symbolic")
                image.add_css_class("route-arrow")
                box.append(image)
                return box, image

            arrow_box, arrow = connector()
            set_accessible_label(arrow, _("{operation} data flow direction").format(operation=operation.title()))
            route.append(arrow_box)
            self.route_arrows = [arrow]

            operation_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            operation_card.add_css_class("operation-card")
            operation_intro = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            operation_header = Gtk.Box(spacing=8)
            operation_header.append(Gtk.Label(label="2", css_classes=["step-number"]))
            operation_header.append(Gtk.Label(label=_("PLAN"), css_classes=["eyebrow"]))
            operation_intro.append(operation_header)
            operation_identity = Gtk.Box(spacing=12)
            operation_identity.add_css_class("identity-row")
            operation_identity.set_size_request(-1, 72)
            op_icon = Gtk.Image.new_from_icon_name(
                "document-save-symbolic" if operation == "backup" else
                "document-revert-symbolic" if operation == "restore" else
                "edit-copy-symbolic"
            )
            op_icon.set_pixel_size(28)
            op_icon.add_css_class("operation-icon")
            op_icon_frame = Gtk.Box()
            op_icon_frame.add_css_class("operation-icon-frame")
            op_icon_frame.append(op_icon)
            operation_identity.append(op_icon_frame)
            op_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            op_label = Gtk.Label(
                label=_("Backup plan") if operation == "backup" else
                _("Restore plan") if operation == "restore" else _("Clone plan"),
                wrap=True,
            )
            op_label.add_css_class("card-title")
            op_text.append(op_label)
            operation_subtitles = {
                "backup": _("Full disk backup"),
                "restore": _("Full disk restore"),
                "clone": _("Direct disk copy"),
            }
            op_text.append(Gtk.Label(
                label=operation_subtitles[operation], xalign=0, css_classes=["muted"]
            ))
            operation_identity.append(op_text)
            operation_intro.append(operation_identity)
            operation_card.append(operation_intro)
            operation_card.append(Gtk.Separator())

            def metric(icon_name: str, label: str, value: str) -> Gtk.Box:
                row = Gtk.Box(spacing=9)
                row.add_css_class("metric-row")
                row.append(Gtk.Image.new_from_icon_name(icon_name))
                row.append(Gtk.Label(label=label, xalign=0, hexpand=True))
                value_label = Gtk.Label(
                    label=value,
                    xalign=1,
                    halign=Gtk.Align.END,
                    wrap=True,
                    max_width_chars=12,
                    css_classes=["setting-value", "metric-value"],
                )
                row.append(value_label)
                self.metric_values[label] = value_label
                return row

            operation_metrics = {
                "backup": (
                    ("drive-harddisk-symbolic", _("Estimated data"), "—"),
                    ("preferences-system-symbolic", _("Compression"), _("Zstandard")),
                    ("security-high-symbolic", _("Verification"), _("Enabled")),
                    ("dialog-warning-symbolic", _("Rescue mode"), _("Disabled")),
                ),
                "restore": (
                    ("security-high-symbolic", _("Image check"), _("Before restore")),
                    ("drive-harddisk-symbolic", _("Partition layout"), _("Preserve")),
                    ("view-fullscreen-symbolic", _("Resize"), _("Disabled")),
                    ("media-floppy-symbolic", _("Boot loader"), _("Restore")),
                    ("dialog-warning-symbolic", _("Size check"), _("Enabled")),
                ),
                "clone": (
                    ("edit-copy-symbolic", _("Copy mode"), _("Direct")),
                    ("drive-harddisk-symbolic", _("Partition layout"), _("Preserve")),
                    ("view-fullscreen-symbolic", _("Resize"), _("Disabled")),
                    ("dialog-warning-symbolic", _("Rescue mode"), _("Disabled")),
                    ("dialog-warning-symbolic", _("Size check"), _("Enabled")),
                ),
            }
            for metric_values in operation_metrics[operation]:
                operation_card.append(metric(*metric_values))
            route.append(operation_card)
            arrow_box2, arrow2 = connector()
            route.append(arrow_box2)
            self.route_arrows.append(arrow2)

            destination_is_repo = operation == "backup"
            destination_role = _("Destination")
            destination_prompt = _("Choose an image folder") if destination_is_repo else _("Choose a drive")

            def choose_destination() -> None:
                if destination_is_repo:
                    choose_repository(self._set_repository)
                else:
                    image = self.selection.get("source")
                    if (operation == "restore" and isinstance(image, ImageCandidate)
                            and len(image.topology.disks) > 1 and self._open_restore_mapping):
                        self._open_restore_mapping(image, self._set_mapped_destinations)
                    elif (operation == "restore" and isinstance(image, ImageCandidate)
                          and image.image_type is ImageType.SAVEPARTS
                          and len(image.topology.partitions) > 1):
                        self._choose_restore_partition(image)
                    else:
                        open_picker("devices", _("Choose destination"), lambda item: self._set_item("destination", item))

            self.destination = SelectionCard(
                destination_role, destination_prompt,
                "folder-symbolic" if destination_is_repo else "drive-harddisk-symbolic",
                choose_destination, self._set_repository if destination_is_repo else None,
                step=3,
            )
            if operation != "backup":
                self.destination.add_css_class("destructive-zone")
            route.append(self.destination)
            card_widths = shared_card_widths or Gtk.SizeGroup(
                mode=Gtk.SizeGroupMode.HORIZONTAL
            )
            card_heights = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.VERTICAL)
            intro_heights = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.VERTICAL)
            for card in (self.source, operation_card, self.destination):
                card.set_valign(Gtk.Align.START)
                card_widths.add_widget(card)
                card_heights.add_widget(card)
            for intro in (self.source.intro, operation_intro, self.destination.intro):
                intro_heights.add_widget(intro)
            self.card_widths = card_widths
            self.card_heights = card_heights
            self.intro_heights = intro_heights
            route_column.append(route)

            if operation == "backup":
                image_name_row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
                image_name_row.append(Gtk.Label(label=_("Image name"), xalign=0, css_classes=["setting-label"]))
                generated_name = f"transume-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
                self.image_name = Gtk.Entry(text=generated_name, placeholder_text=_("Safe image name"))
                set_accessible_label(self.image_name, _("Backup image name"))
                image_name_row.append(self.image_name)
                self.image_name_status = Gtk.Label(xalign=0, css_classes=["muted"])
                image_name_row.append(self.image_name_status)
                def image_name_changed(entry: Gtk.Entry) -> None:
                    name = entry.get_text().strip()
                    self.draft.image_name = name or None
                    repository = self.draft.repository
                    if not name:
                        self.image_name_status.set_label(_("Enter an image name."))
                    elif not __import__("re").fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
                        self.image_name_status.set_label(_("Use letters, digits, dot, underscore, or hyphen only."))
                    elif repository is not None and (repository / name).exists():
                        self.image_name_status.set_label(_("An image with this name already exists."))
                    else:
                        self.image_name_status.set_label(_("Available"))
                    self._update_ready()
                self.image_name.connect("changed", image_name_changed)
                image_name_changed(self.image_name)
                route_column.append(image_name_row)

            route_hint = Gtk.Box(spacing=8)
            route_hint.add_css_class("route-hint")
            route_hint.append(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
            route_hint.append(Gtk.Label(
                label=_("Source devices must be unmounted. System disks require a live session."),
                xalign=0, wrap=True,
            ))
            route_column.append(route_hint)
            workspace.append(route_column)

            context = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
            context.add_css_class("context-panel")
            context.set_vexpand(True)
            self.context = context
            context_scroll = Gtk.ScrolledWindow(
                hscrollbar_policy=Gtk.PolicyType.NEVER,
                vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
                vexpand=True,
                min_content_width=220,
                max_content_width=220,
                propagate_natural_width=False,
            )
            context_scroll.set_hexpand(False)
            context_scroll.set_child(context)
            self.context_scroll = context_scroll
            self.context_expander = Gtk.Expander(label=_("{operation} settings").format(operation=operation.title()))
            self.context_expander.add_css_class("compact-settings")
            self.context_expander.set_expanded(True)
            if shared_context_widths is not None:
                shared_context_widths.add_widget(context_scroll)
            context_header = Gtk.Box(spacing=9)
            context_header.append(Gtk.Image.new_from_icon_name("emblem-system-symbolic"))
            context_header.append(Gtk.Label(
                label=_("{operation} settings").format(operation=operation.title()), xalign=0,
                css_classes=["context-title"],
            ))
            context.append(context_header)
            advanced_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)

            if operation == "backup":
                self.settings.update({"compression": "zstd", "engine": "partclone",
                                      "verify_image": True, "rescue": False, "filesystem_check": "check",
                                      "checksum": "none", "image_size": 0, "encrypt": False, "post_action": "none"})
                self._sync_draft_options()
                caps = getattr(model, "capabilities", None)
                installed_compressors = {
                    "zstd": _("Zstandard"), "lz4": "LZ4", "gzip": _("Gzip"), "xz": "XZ", "lzma": "LZMA",
                    "bzip2": "Bzip2", "lzo": "LZO", "lzip": "Lzip", "lrzip": "LRzip",
                }
                compressor_tools = {"zstd": {"zstd", "zstdmt"}, "lz4": {"lz4", "lz4mt"}, "gzip": {"gzip", "pigz"},
                                    "xz": {"xz", "pixz"}, "lzma": {"lzma"}, "bzip2": {"bzip2", "pbzip2"}, "lzo": {"lzop"},
                                    "lzip": {"lzip", "plzip"}, "lrzip": {"lrzip"}}
                compression_values = [key for key in installed_compressors if caps is None or compressor_tools[key] & caps.compressors]
                compression_values.append("none")
                if "zstd" not in compression_values:
                    self._set_option("compression", compression_values[0])
                context.append(Gtk.Label(label=_("COMPRESSION"), xalign=0, css_classes=["setting-label"]))
                compression = Gtk.DropDown.new_from_strings([installed_compressors.get(value, _("None")) for value in compression_values])
                style_dropdown(compression)
                set_accessible_label(compression, _("Compression level"))
                def compression_changed(control: Gtk.DropDown, _detail: Any) -> None:
                    value = compression_values[control.get_selected()]
                    self._set_option("compression", value)
                    self.metric_values["Compression"].set_label(control.get_selected_item().get_string())
                compression.connect("notify::selected", compression_changed)
                context.append(compression)
                advanced_box.append(Gtk.Label(label=_("BACKUP ENGINE"), xalign=0, css_classes=["setting-label"]))
                engines = [("partclone", "Partclone", "partclone"), ("dd", "dd", "dd"), ("ntfsclone", "NTFSClone", "ntfsclone")]
                engines = [value for value in engines if caps is None or caps.supports(value[2])]
                if engines and not any(value[0] == self.settings["engine"] for value in engines):
                    self._set_option("engine", engines[0][0])
                engine = Gtk.DropDown.new_from_strings([value[1] for value in engines])
                style_dropdown(engine)
                engine.set_tooltip_text(_("Only installed Clonezilla copy engines are shown."))
                engine.connect("notify::selected", lambda control, _detail: self._set_option("engine", engines[control.get_selected()][0]))
                advanced_box.append(engine)
                advanced_box.append(Gtk.Label(label=_("FILESYSTEM CHECK"), xalign=0, css_classes=["setting-label"]))
                fsck_values = ("skip", "check", "repair")
                fsck = Gtk.DropDown.new_from_strings([_("Skip"), _("Check"), _("Check and repair")])
                style_dropdown(fsck)
                fsck.connect("notify::selected", lambda control, _detail: self._set_option("filesystem_check", fsck_values[control.get_selected()]))
                advanced_box.append(fsck)
                advanced_box.append(Gtk.Label(label=_("CHECKSUM"), xalign=0, css_classes=["setting-label"]))
                checksum_values = ("none", "md5", "sha1", "files")
                checksum = Gtk.DropDown.new_from_strings([_("None"), "MD5", "SHA-1", _("File list")])
                style_dropdown(checksum)
                checksum.connect("notify::selected", lambda control, _detail: self._set_option("checksum", checksum_values[control.get_selected()]))
                advanced_box.append(checksum)
                split = Gtk.SpinButton.new_with_range(0, 4_194_304, 1)
                split.add_css_class("setting-spin")
                split.set_tooltip_text(_("Split size in MiB. Zero uses Clonezilla automatic sizing."))
                split.connect("value-changed", lambda control: self._set_option("image_size", int(control.get_value())))
                advanced_box.append(Gtk.Label(
                    label=_("Split size (MiB, 0 = automatic)"), xalign=0, wrap=True,
                    max_width_chars=22, css_classes=["setting-label"],
                )); advanced_box.append(split)
                if caps is None or caps.supports("ecryptfs"):
                    encrypt = Gtk.CheckButton(label=_("Encrypt backup"))
                    encrypt.set_tooltip_text(_("A passphrase is requested only after Review and is never included in the plan or command preview."))
                    encrypt.connect("toggled", lambda control: self._set_option("encrypt", control.get_active()))
                    self.encrypt_control = encrypt
                    context.append(encrypt)
                else:
                    unavailable = Gtk.Label(label=_("Encryption unavailable: native eCryptfs tools are not installed."), xalign=0, wrap=True, css_classes=["muted"])
                    context.append(unavailable)
                context.append(Gtk.Separator())
                verify = Gtk.CheckButton(label=_("Verify after completion"))
                verify.set_active(True)
                def verify_changed(control: Gtk.CheckButton) -> None:
                    active = control.get_active()
                    self._set_option("verify_image", active)
                    self.metric_values[_("Verification")].set_label(_("Enabled") if active else _("Disabled"))
                verify.connect("toggled", verify_changed)
                self.verify_control = verify
                context.append(verify)
                rescue = Gtk.CheckButton(label=_("Rescue damaged sectors"))
                def rescue_changed(control: Gtk.CheckButton) -> None:
                    active = control.get_active()
                    self._set_option("rescue", active)
                    self.metric_values[_("Rescue mode")].set_label(_("Enabled") if active else _("Disabled"))
                rescue.connect("toggled", rescue_changed)
                advanced_box.append(rescue)
            elif operation == "restore":
                self.settings.update({"check_image": True, "resize": False, "restore_mbr": True,
                                      "partition_table": "original"})
                self._sync_draft_options()
                context.append(Gtk.Label(label=_("RESTORE"), xalign=0, css_classes=["setting-label"]))
                check_image = Gtk.CheckButton(label=_("Check image before restore"))
                check_image.set_active(True)
                def check_changed(control: Gtk.CheckButton) -> None:
                    active = control.get_active()
                    self._set_option("check_image", active)
                    self.metric_values[_("Image check")].set_label(_("Before restore") if active else _("Skipped"))
                check_image.connect("toggled", check_changed)
                context.append(check_image)
                advanced_box.append(Gtk.Label(label=_("RESTORE LAYOUT"), xalign=0, css_classes=["setting-label"]))
                resize = Gtk.CheckButton(label=_("Resize filesystem to fit"))
                def resize_changed(control: Gtk.CheckButton) -> None:
                    active = control.get_active()
                    self._set_option("resize", active)
                    self.metric_values[_("Resize")].set_label(_("Enabled") if active else _("Disabled"))
                resize.connect("toggled", resize_changed)
                advanced_box.append(resize)
                restore_boot = Gtk.CheckButton(label=_("Restore boot loader"))
                restore_boot.set_active(True)
                def boot_changed(control: Gtk.CheckButton) -> None:
                    active = control.get_active()
                    self._set_option("restore_mbr", active)
                    self.metric_values[_("Boot loader")].set_label(_("Restore") if active else _("Skip"))
                restore_boot.connect("toggled", boot_changed)
                advanced_box.append(restore_boot)
                for key, label in (("restore_ebr", _("Restore EBR")), ("hidden_data", _("Restore hidden data")),
                                   ("update_efi", _("Update EFI boot entries"))):
                    control = Gtk.CheckButton(label=label)
                    control.set_active(bool(self.settings.get(key, key in {"restore_ebr", "update_efi"})))
                    control.connect("toggled", lambda button, setting=key: self._set_option(setting, button.get_active()))
                    advanced_box.append(control)
                table_values = ("original", "proportional", "existing")
                table = Gtk.DropDown.new_from_strings([_("Original partition table"), _("Proportional"), _("Use existing table")])
                style_dropdown(table)
                table.set_tooltip_text(_("Existing layout is unavailable for old images without partition metadata."))
                table.connect("notify::selected", lambda control, _detail: self._set_option("partition_table", table_values[control.get_selected()]))
                advanced_box.append(table)
            else:
                self.settings.update({"resize": False, "rescue": False, "force_dd": False,
                                      "hidden_data": False})
                self._sync_draft_options()
                advanced_box.append(Gtk.Label(label=_("CLONE METHOD"), xalign=0, css_classes=["setting-label"]))
                clone_controls = (
                    ("resize", _("Resize filesystem to fit"), _("Resize"), _("Enabled")),
                    ("rescue", _("Rescue damaged sectors"), _("Rescue mode"), _("Enabled")),
                    ("force_dd", _("Sector-by-sector copy"), _("Copy mode"), _("Sector-by-sector")),
                    ("direct_io", _("Use direct I/O"), _("Copy mode"), _("Direct I/O")),
                    ("hidden_data", _("Copy hidden data"), _("Partition layout"), _("Include hidden")),
                )
                for key, label, metric_name, enabled_text in clone_controls:
                    control = Gtk.CheckButton(label=label)
                    def changed(button: Gtk.CheckButton, setting=key,
                                summary=metric_name, enabled=enabled_text) -> None:
                        active = button.get_active()
                        self._set_option(setting, active)
                        self.metric_values[summary].set_label(
                            enabled if active else (_("Direct") if setting == "force_dd" else _("Disabled"))
                        )

                    control.connect("toggled", changed)
                    setattr(self, f"clone_{key}_control", control)
                    advanced_box.append(control)
            advanced_box.append(Gtk.Label(label=_("AFTER COMPLETION"), xalign=0, css_classes=["setting-label"]))
            post_actions = ("none", "poweroff", "reboot")
            post_action = Gtk.DropDown.new_from_strings([_("Do nothing"), _("Power off"), _("Reboot")])
            style_dropdown(post_action)
            post_action.set_tooltip_text(_("The selected action is passed to Clonezilla after a successful job."))
            post_action.connect("notify::selected", lambda control, _detail: self._set_option("post_action", post_actions[control.get_selected()]))
            advanced_box.append(post_action)
            context.append(Gtk.Separator())
            advanced_revealer = Gtk.Revealer(
                transition_type=Gtk.RevealerTransitionType.SLIDE_DOWN,
                transition_duration=140,
            )
            advanced_revealer.set_child(advanced_box)
            self.advanced_revealer = advanced_revealer
            advanced_toggle = Gtk.Button()
            self.advanced_toggle = advanced_toggle
            advanced_toggle.add_css_class("advanced-row")
            advanced_content = Gtk.Box(spacing=10)
            advanced_icon_leading = Gtk.Image.new_from_icon_name(
                "preferences-system-symbolic"
            )
            advanced_icon_leading.set_pixel_size(18)
            advanced_content.append(advanced_icon_leading)
            advanced_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            advanced_text.set_hexpand(True)
            advanced_text.append(Gtk.Label(
                label=_("Advanced options"), xalign=0,
                css_classes=["advanced-title"],
            ))
            advanced_text.append(Gtk.Label(
                label=_("Compatibility and recovery"), xalign=0,
                ellipsize=Pango.EllipsizeMode.END,
                css_classes=["muted", "advanced-subtitle"],
            ))
            advanced_content.append(advanced_text)
            advanced_icon = Gtk.Image.new_from_icon_name("go-down-symbolic")
            advanced_content.append(advanced_icon)
            advanced_toggle.set_child(advanced_content)
            advanced_toggle.set_tooltip_text(_("Show advanced Clonezilla options"))
            advanced_expanded = False

            def toggle_advanced(button: Gtk.Button) -> None:
                nonlocal advanced_expanded
                advanced_expanded = not advanced_expanded
                advanced_revealer.set_reveal_child(advanced_expanded)
                advanced_icon.set_from_icon_name(
                    "go-up-symbolic" if advanced_expanded else "go-down-symbolic"
                )
                button.set_tooltip_text(
                    _("Hide advanced Clonezilla options") if advanced_expanded
                    else _("Show advanced Clonezilla options")
                )

            advanced_toggle.connect("clicked", toggle_advanced)
            context.append(advanced_toggle)
            context.append(advanced_revealer)
            context.append(Gtk.Box(vexpand=True))
            scroll.set_child(body)
            content_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            content_row.set_vexpand(True)
            content_row.append(scroll)
            content_row.append(context_scroll)
            self.body = body
            self.workspace = workspace
            self.content_row = content_row
            body.append(workspace)
            self.append(content_row)

            bar = Gtk.Box(spacing=12)
            bar.add_css_class("action-bar")
            back = Gtk.Button()
            back_content = Gtk.Box(spacing=6)
            back_content.append(Gtk.Image.new_from_icon_name("go-previous-symbolic"))
            back_content.append(Gtk.Label(label=_("Back")))
            back.set_child(back_content)
            back.set_tooltip_text(_("Return to the previous screen"))
            if self._on_back is not None:
                back.connect("clicked", lambda _button: self._on_back())
            else:
                back.set_sensitive(False)
            bar.append(back)
            spacer = Gtk.Box(hexpand=True)
            bar.append(spacer)
            review_button = Gtk.Button(label=_("Review {operation}").format(operation=operation))
            review_button.add_css_class("suggested-action")
            review_button.set_sensitive(False)
            self.review_button = review_button
            review_button.connect("clicked", lambda _button: self._review())
            bar.append(review_button)
            self.append(bar)

        def set_compact(self, compact: bool) -> None:
            self.route.set_orientation(
                Gtk.Orientation.VERTICAL if compact else Gtk.Orientation.HORIZONTAL
            )
            icon = "go-down-symbolic" if compact else "go-next-symbolic"
            for arrow in self.route_arrows:
                arrow.set_from_icon_name(icon)
            if compact and self.context_scroll.get_parent() is self.content_row:
                self.content_row.remove(self.context_scroll)
                # The page already scrolls. A nested scrolled window collapses
                # settings into a narrow strip and traps the remaining controls.
                self.context_scroll.set_child(None)
                self.context.set_vexpand(False)
                self.context_expander.set_child(self.context)
                self.body.append(self.context_expander)
            elif not compact and self.context_expander.get_parent() is self.body:
                self.body.remove(self.context_expander)
                self.context_expander.set_child(None)
                self.context.set_vexpand(True)
                self.context_scroll.set_child(self.context)
                self.content_row.append(self.context_scroll)

        def _set_option(self, key: str, value: str | bool | int) -> None:
            self.settings[key] = value
            if self.draft.options is not None:
                setattr(self.draft.options, key, value)

        def _sync_draft_options(self) -> None:
            for key, value in self.settings.items():
                self._set_option(key, value)

        def _set_item(self, role: str, item: Any) -> None:
            title = model_value(item, "name") or model_value(item, "model", _("Selected item"))
            detail = " · ".join(x for x in (model_value(item, "path"), model_value(item, "size")) if x)
            self.selection[role] = item
            if role == "source":
                self.draft.set_source(item)
                if self.operation == "restore" and isinstance(item, ImageCandidate):
                    selected = (item.source_partitions[0]
                                if item.image_type is ImageType.SAVEPARTS
                                and len(item.source_partitions) == 1 else "")
                    self._set_option("source_partition", selected)
            else:
                self.draft.set_destination(item)
            identity = getattr(item, "identity", None)
            stable_id = ""
            if identity is not None:
                if identity.serial:
                    stable_id = _("Serial: {serial}").format(serial=identity.serial)
                elif identity.wwn:
                    stable_id = _("WWN: {wwn}").format(wwn=identity.wwn)
                elif identity.by_id:
                    stable_id = _("ID: {id}").format(id=Path(identity.by_id[0]).name)
            elif role == "source" and self.operation == "restore":
                status = model_value(item, "status")
                status = status.replace("-", " ").title()
                stable_id = _("Image status: {status}").format(status=status) if status else _("Clonezilla image")
            (self.source if role == "source" else self.destination).set_selection(
                title, detail or _("Selected"), stable_id,
            )
            self._update_ready()

        def _choose_restore_partition(self, image: ImageCandidate) -> None:
            root = self.get_root()
            if not isinstance(root, Gtk.Window):
                return
            dialog, content = dialog_shell(
                root, _("Choose source partition"),
                _("Clonezilla can map one selected image partition to one target partition."),
                width=520, icon_name="drive-harddisk-symbolic",
            )
            listing = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)

            def selected(partition: Any) -> None:
                self._set_option("source_partition", partition.name)
                dialog.destroy()
                self._open_picker(
                    "devices",
                    _("Choose destination for {partition}").format(partition=partition.name),
                    lambda item: self._set_item("destination", item),
                )

            for partition in image.topology.partitions:
                button = Gtk.Button(css_classes=["info-card", "partition-choice"])
                row = Gtk.Box(spacing=10)
                row.append(Gtk.Image.new_from_icon_name("drive-harddisk-symbolic"))
                detail = partition.filesystem or _("Filesystem unknown")
                if partition.size is not None:
                    detail = _("{filesystem}, {size} bytes").format(
                        filesystem=detail, size=partition.size,
                    )
                labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
                labels.append(Gtk.Label(label=partition.name, xalign=0, css_classes=["card-title"]))
                labels.append(Gtk.Label(label=detail, xalign=0, css_classes=["muted"]))
                row.append(labels)
                button.set_child(row)
                button.connect("clicked", lambda _button, value=partition: selected(value))
                listing.append(button)
            content.append(listing)
            actions = dialog_actions(content)
            cancel = Gtk.Button(label=_("Cancel"))
            cancel.connect("clicked", lambda _button: dialog.destroy())
            actions.append(cancel)
            dialog.present()

        def _set_repository(self, path: Path) -> None:
            self.selection["destination"] = path
            self.draft.repository = path
            self.destination.set_selection(
                path.name or str(path), str(path), _("Storage folder"),
            )
            if hasattr(self, "image_name"):
                self.image_name.emit("changed")
            self._update_ready()

        def _set_mapped_destinations(self, values: list[Any]) -> None:
            self.draft.set_destinations(values)
            self.selection["destination"] = values[0] if values else None
            names = ", ".join(model_value(value, "name") or model_value(value, "path", "Target") for value in values)
            self.destination.set_selection(_("{count} mapped targets").format(count=len(values)), names, _("Explicit disk mapping"))
            self._update_ready()

        def _drop_source(self, path: Path) -> None:
            self.selection["source"] = path
            self.draft.set_source(path)
            self.source.set_selection(path.name, str(path), _("Local image path"))
            self._update_ready()

        def _update_ready(self) -> None:
            if not hasattr(self, "review_button"):
                return
            complete = bool(self.selection.get("source") and self.selection.get("destination"))
            if self.operation == "backup":
                name = self.draft.image_name or ""
                complete = complete and bool(__import__("re").fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name))
                if self.draft.repository is not None and (self.draft.repository / name).exists():
                    complete = False
            self.review_button.set_sensitive(complete)
            self.review_button.set_tooltip_text(
                None if complete else "Choose source and destination first"
            )

        def _review(self) -> None:
            if self.selection.get("source") and self.selection.get("destination"):
                self.review_callback(self.draft)


    class RestoreMappingPage(Gtk.Box):
        """Explicit ordered source-disk to target-disk mapping."""
        __gtype_name__ = "TransumeRestoreMappingPage"

        def __init__(self, image: ImageCandidate, choose: Callable[[int], None],
                     complete: Callable[[], None], back: Callable[[], None]) -> None:
            super().__init__(orientation=Gtk.Orientation.VERTICAL)
            self.targets: list[Any | None] = [None] * len(image.topology.disks)
            scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                           css_classes=["page"])
            body.append(page_heading(_("Map restore disks"), _("Choose one unique target for each source disk. Order is preserved.")))
            for index, disk in enumerate(image.topology.disks):
                row = Gtk.Box(spacing=12, css_classes=["info-card", "mapping-row"])
                icon = Gtk.Image.new_from_icon_name("drive-harddisk-symbolic")
                icon.set_pixel_size(28)
                icon.add_css_class("muted")
                row.append(icon)
                partition_count = len(disk.partitions)
                size = str(disk.size) if disk.size is not None else _("size unknown")
                label = Gtk.Label(label=_("{name}  {model}  {size}  {partitions} partitions").format(name=disk.name, model=disk.model or _("Unknown model"), size=size, partitions=partition_count), xalign=0, hexpand=True, wrap=True)
                row.append(label)
                button = Gtk.Button(label=_("Choose target"))
                button.connect("clicked", lambda _button, value=index: choose(value))
                row.append(button)
                setattr(self, f"target_button_{index}", button)
                body.append(row)
            scroll.set_child(body)
            self.append(scroll)
            actions = Gtk.Box(spacing=8, css_classes=["action-bar"])
            back_button = Gtk.Button(label=_("Back"))
            back_button.connect("clicked", lambda _button: back())
            actions.append(back_button)
            actions.append(Gtk.Box(hexpand=True))
            self.complete_button = Gtk.Button(label=_("Use mapping"), css_classes=["suggested-action"])
            self.complete_button.set_sensitive(False)
            self.complete_button.connect("clicked", lambda _button: complete())
            actions.append(self.complete_button)
            self.append(actions)

        def set_target(self, index: int, item: Any) -> None:
            self.targets[index] = item
            self.__getattribute__(f"target_button_{index}").set_label(model_value(item, "name") or model_value(item, "path", _("Target")))
            identities = [getattr(value, "identity", None) for value in self.targets if value is not None]
            self.complete_button.set_sensitive(len(identities) == len(self.targets) and len({value.path for value in identities}) == len(identities))


    class ImageBrowserPage(Gtk.Box):
        """Choose a Clonezilla image from a user-authorized local folder."""

        __gtype_name__ = "TransumeImageBrowserPage"

        def __init__(
            self,
            model: Any,
            open_folder: Callable[[Callable[[Path], None]], None],
            on_select: Callable[[ImageCandidate], None],
            on_back: Callable[[], None],
            image_controls: Callable[[ImageCandidate, Callable[[], None]], tuple[Gtk.Widget, str | None]] | None = None,
        ) -> None:
            super().__init__(orientation=Gtk.Orientation.VERTICAL)
            self.model = model
            self.open_folder_callback = open_folder
            self.on_select = on_select
            self.on_back = on_back
            self.image_controls = image_controls
            self.location: Path | None = None
            self.images: list[ImageCandidate] = []
            self._state = "initial"
            self._selected: ImageCandidate | None = None
            self._scan_token = 0
            self._scan_cancel: threading.Event | None = None
            self._scan_problems: list[str] = []

            scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
            self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            self.body.add_css_class("page")
            scroll.set_child(self.body)
            self.append(scroll)
            bar = Gtk.Box(spacing=12)
            bar.add_css_class("action-bar")
            back = Gtk.Button(label=_("Back"))
            back.connect("clicked", lambda _button: self.on_back())
            bar.append(back)
            self.append(bar)
            self._render()

        def _clear_body(self) -> None:
            while child := self.body.get_first_child():
                self.body.remove(child)

        @staticmethod
        def _label(text: str, *, style: str | None = None, selectable: bool = False) -> Gtk.Label:
            label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=selectable)
            label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            label.set_ellipsize(Pango.EllipsizeMode.END)
            label.set_max_width_chars(72)
            if style:
                label.add_css_class(style)
            return label

        def _render(self) -> None:
            self._clear_body()
            self.body.append(page_heading(
                _("Choose a restore image"),
                _("A Clonezilla image is a folder containing its metadata and image data."),
            ))
            location = Gtk.Box(spacing=12)
            location.add_css_class("info-card")
            location_text = str(self.location) if self.location else _("No folder selected")
            location_label = self._label(location_text)
            if self.location:
                location_label.set_tooltip_text(location_text)
            location.append(location_label)
            location.append(Gtk.Box(hexpand=True))
            change = Gtk.Button(label=_("Change folder") if self.location else _("Open folder"))
            change.connect("clicked", lambda _button: self.open_folder_callback(self.set_folder))
            location.append(change)
            self.body.append(location)

            if self._state == "initial":
                message = _("Open the folder that contains your Clonezilla image folders.")
            elif self._state == "loading":
                message = _("Scanning this folder for Clonezilla images...")
                cancel = Gtk.Button(label=_("Cancel scan"))
                cancel.connect("clicked", lambda _button: self.cancel_scan())
                self.body.append(cancel)
            elif self._state == "error":
                message = self._error
            elif self._state == "empty":
                message = _("No Clonezilla image folders were found here. Choose another folder to continue.")
            else:
                self._render_images()
                if self._scan_problems:
                    self.body.append(self._label(_("Scan notes: {notes}").format(notes="; ".join(self._scan_problems)[:600]), style="muted"))
                return
            state = self._label(message, style="empty-state")
            state.set_justify(Gtk.Justification.CENTER)
            self.body.append(state)

        def set_folder(self, path: Path) -> None:
            self.location = path
            self._selected = None
            self._start_scan()

        def cancel_scan(self) -> None:
            if self._scan_cancel is not None:
                self._scan_cancel.set()
            self._scan_token += 1
            self._state = "initial"
            self._render()

        def _start_scan(self) -> None:
            self.cancel_scan()
            self._scan_token += 1
            token = self._scan_token
            cancel = threading.Event()
            self._scan_cancel = cancel
            self._state = "loading"
            self._render()
            try:
                setter = getattr(self.model, "set_repository", None)
                if getattr(self.model, "repository", None) != self.location and callable(setter):
                    setter(self.location)
                catalog = getattr(self.model, "catalog", None)
                location_id = getattr(self.model, "_repository_location_id", None)
                if catalog is not None and location_id:
                    future = catalog.scan_async(location_id, self.location, cancel_event=cancel)
                    def complete(completed: Any) -> None:
                        try:
                            value, failure = completed.result(), None
                        except Exception as error:
                            value, failure = None, error
                        GLib.idle_add(self._scan_finished, token, value, failure)
                    future.add_done_callback(complete)
                    return
                images = getattr(self.model, "list_images", None)
                if not callable(images):
                    raise RuntimeError("Image discovery is unavailable")
                def worker() -> None:
                    try:
                        result = list(images())
                        GLib.idle_add(self._scan_finished, token, result, None)
                    except Exception as error:
                        GLib.idle_add(self._scan_finished, token, None, error)
                threading.Thread(target=worker, name="transume-image-scan", daemon=True).start()
            except Exception as error:
                self._scan_finished(token, None, error)

        def _scan(self) -> bool:
            self._start_scan()
            return GLib.SOURCE_REMOVE

        def _scan_finished(self, token: int, result: Any, error: Exception | None) -> bool:
            if token != self._scan_token:
                return GLib.SOURCE_REMOVE
            try:
                if error is not None:
                    raise error
                if hasattr(result, "candidates"):
                    self.images = list(result.candidates)
                    self._scan_problems = [problem.message for problem in result.problems]
                    if result.partial:
                        self._scan_problems.append(_("Scan cancelled; results are partial."))
                else:
                    self.images = list(result or [])
                    self._scan_problems = []
                self._state = "ready" if self.images else "empty"
            except Exception as scan_error:
                self.images = []
                self._error = _("Could not scan this folder: {error}").format(error=str(scan_error)[:240])
                self._state = "error"
            self._render()
            return GLib.SOURCE_REMOVE

        def _render_images(self) -> None:
            search = Gtk.SearchEntry(placeholder_text=_("Search image name, disk, or path"))
            self.body.append(search)
            listing = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, hexpand=True)
            listing.add_css_class("image-card-list")
            list_scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
            list_scroll.set_child(listing)
            self.body.append(list_scroll)
            self.image_list = listing
            widgets: list[tuple[Gtk.Widget, str]] = []
            for image in self.images:
                menu, notice = self.image_controls(image, self._start_scan) if self.image_controls else (None, None)
                row = Gtk.ListBoxRow(activatable=True, selectable=True)
                row.add_css_class("image-picker-row")
                row.set_child(ImageCard(image, action_menu=menu, notice=notice))
                row.image = image
                listing.append(row)
                widgets.append((row, " ".join((
                    image.name, str(image.path), *image.source_disks,
                    *image.source_partitions, *image.compression,
                )).casefold()))
            self.image_rows = widgets
            listing.connect(
                "row-activated",
                lambda _list, row: not row.image.problems and self.on_select(row.image),
            )

            def filter_rows(entry: Gtk.SearchEntry) -> None:
                query = entry.get_text().casefold()
                for row, searchable in widgets:
                    row.set_visible(query in searchable)

            search.connect("search-changed", filter_rows)

    class ImagesPage(Gtk.ScrolledWindow):
        __gtype_name__ = "TransumeImagesPage"

        def __init__(self, model: Any, choose_folder: Callable[[Callable[[Path], None]], None], picker: Callable[[str, str, Callable[[Any], None]], None], review: Callable[..., None], explorer: Any = None, restore_image: Callable[[ImageCandidate], None] | None = None) -> None:
            super().__init__(hscrollbar_policy=Gtk.PolicyType.NEVER)
            self.model, self.choose_folder, self.picker, self.review, self.explorer = model, choose_folder, picker, review, explorer
            self.restore_image = restore_image
            self.explorer_sessions: set[str] = set()
            self.explorer_pending = False
            self.compact = False
            self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
            self.body.add_css_class("page")
            self.set_child(self.body)
            self._render()

        def _set_repo(self, path: Path) -> None:
            try:
                if getattr(self.model, "repository", None) != path:
                    self.model.set_repository(path)
            except Exception as error:
                self._dialog(_("Could not open folder"), str(error))
                return
            self._render()

        def _dialog(self, title: str, detail: str) -> None:
            dialog = Gtk.Dialog(transient_for=self.get_root(), modal=True, title=title)
            dialog.set_default_size(480, 1)
            content = dialog.get_content_area()
            content.set_spacing(16)
            content.set_margin_top(18); content.set_margin_bottom(16)
            content.set_margin_start(18); content.set_margin_end(18)
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, css_classes=["info-card"])
            card.append(Gtk.Label(label=title, xalign=0, css_classes=["card-title"]))
            card.append(Gtk.Label(label=detail, xalign=0, wrap=True, selectable=True, css_classes=["muted"]))
            content.append(card)
            actions = Gtk.Box(halign=Gtk.Align.END, css_classes=["dialog-actions"])
            close = Gtk.Button(label=_("Close"))
            close.connect("clicked", lambda _button: dialog.destroy())
            actions.append(close)
            content.append(actions)
            dialog.present()

        def _render(self) -> None:
            while child := self.body.get_first_child():
                self.body.remove(child)
            self.body.append(page_heading(_("Images"), _("Choose a folder to inspect current image status.")))
            location = Gtk.Box(spacing=12, css_classes=["info-card"])
            location.append(Gtk.Label(label=str(getattr(self.model, "repository", None) or _("No folder selected")), xalign=0, hexpand=True, wrap=True))
            choose = Gtk.Button(label=_("Choose folder"))
            choose.connect("clicked", lambda _button: self.choose_folder(self._set_repo))
            location.append(choose)
            refresh = Gtk.Button(label=_("Refresh"))
            refresh.connect("clicked", lambda _button: self._render())
            location.append(refresh)
            self.body.append(location)
            images, error = _call_model(self.model, "list_images")
            if error:
                self.body.append(Gtk.Label(label=error, xalign=0, wrap=True, css_classes=["danger-banner"]))
            if not images:
                self.body.append(Gtk.Label(label=_("No Clonezilla image folders found. Choose a folder to scan."), xalign=0, css_classes=["empty-state"]))
                return
            self.image_cards: list[ImageCard] = []
            for image in images:
                self._image_card(image)

        def _supported(self, capability: str) -> bool:
            caps = getattr(self.model, "capabilities", None)
            return caps is not None and caps.supports(capability)

        def _image_card(self, image: ImageCandidate) -> None:
            menu, notice = self.image_controls(image, self._render)
            card = ImageCard(image, action_menu=menu, notice=notice)
            self.image_cards.append(card)
            self.body.append(card)

        def image_controls(self, image: ImageCandidate,
                           refresh: Callable[[], None]) -> tuple[Gtk.Widget, str | None]:
            more = Gtk.MenuButton(icon_name="view-more-symbolic")
            more.set_tooltip_text(_("Images"))
            menu = Gtk.Popover(autohide=True, has_arrow=False)
            menu_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2,
                               css_classes=["compact-navigation", "image-actions-menu"])

            def menu_action(label: str, icon_name: str,
                            callback: Callable[[], None], *, destructive: bool = False,
                            sensitive: bool = True, tooltip: str | None = None) -> None:
                button = Gtk.Button(css_classes=["flat", "compact-nav-item"])
                button.set_sensitive(sensitive)
                button.set_tooltip_text(tooltip)
                content = Gtk.Box(spacing=10)
                icon = Gtk.Image.new_from_icon_name(icon_name)
                icon.set_pixel_size(18)
                content.append(icon)
                content.append(Gtk.Label(label=label, xalign=0, hexpand=True))
                button.set_child(content)
                if destructive:
                    button.add_css_class("destructive-menu-item")
                def activate(_button: Gtk.Button) -> None:
                    menu.popdown()
                    callback()
                button.connect("clicked", activate)
                menu_box.append(button)

            check_usable = image.status in {ImageStatus.READY, ImageStatus.NEEDS_VERIFICATION}
            check_ready = check_usable and self._supported("check-image")
            menu_action(
                _("Restore"), "document-revert-symbolic",
                lambda: self.restore_image(image) if self.restore_image else None,
                sensitive=self.restore_image is not None and not image.problems,
            )
            menu_action(
                _("Check image"), "emblem-ok-symbolic",
                lambda: self._action("check", image), sensitive=check_ready,
                tooltip=None if check_ready else _("Requires a usable image and {capability}").format(capability="check-image"),
            )
            reason = explorer_support_reason(image, capabilities=getattr(self.model, "capabilities", None))
            explore_ready = reason is None and self.explorer is not None
            unavailable = reason or (None if self.explorer is not None else _("Image Explorer is unavailable"))
            menu_action(
                _("Explore files"), "folder-open-symbolic",
                lambda: self._explore(image), sensitive=explore_ready, tooltip=unavailable,
            )
            menu_box.append(Gtk.Separator())
            menu_action(_("Open containing folder"), "folder-open-symbolic",
                        lambda: self._open_folder(image))
            menu_action(_("Rename"), "document-edit-symbolic",
                        lambda: self._rename(image, refresh),
                        sensitive=image.status in {ImageStatus.READY, ImageStatus.NEEDS_VERIFICATION})
            menu_action(_("Delete"), "user-trash-symbolic",
                        lambda: self._delete(image, refresh), destructive=True)
            menu.set_child(menu_box)
            more.set_popover(menu)
            return more, unavailable

        def set_compact(self, compact: bool) -> None:
            if self.compact != compact:
                self.compact = compact
                self._render()

        def _open_folder(self, image: ImageCandidate) -> None:
            try:
                Gio.AppInfo.launch_default_for_uri(self.model.containing_folder_uri(image), None)
            except Exception as error:
                self._dialog(_("Could not open folder"), str(error))

        def _explore(self, image: ImageCandidate) -> None:
            if self.explorer_pending:
                return
            if self.explorer_sessions:
                self.explorer_pending = True
                session = next(iter(self.explorer_sessions))
                def read_status() -> None:
                    try:
                        result = self.explorer.status(uuid4().hex, session)
                        if result.status != "ok" or not result.mountpoint:
                            raise RuntimeError(result.detail)
                        GLib.idle_add(self._explorer_connected, result)
                    except Exception as error:
                        GLib.idle_add(self._explorer_connect_failed, str(error))
                threading.Thread(target=read_status, name="transume-explorer-status", daemon=True).start()
                return
            partitions = tuple(part.name for part in image.topology.partitions)
            if len(partitions) == 1:
                self._connect_explorer(image, partitions[0]); return
            dialog, content = dialog_shell(
                self.get_root(), _("Choose partition"),
                icon_name="drive-harddisk-symbolic",
            )
            chooser = Gtk.DropDown.new_from_strings(list(partitions))
            style_dropdown(chooser)
            chooser.set_hexpand(True)
            set_accessible_label(chooser, _("Choose partition"))
            content.append(chooser)
            actions = dialog_actions(content)
            cancel = Gtk.Button(label=_("Cancel"))
            explore = Gtk.Button(label=_("Explore"), css_classes=["suggested-action"])
            cancel.connect("clicked", lambda _button: dialog.destroy())
            def choose_partition(_button: Gtk.Button) -> None:
                self._connect_explorer(image, partitions[chooser.get_selected()])
                dialog.destroy()
            explore.connect("clicked", choose_partition)
            actions.append(cancel)
            actions.append(explore)
            dialog.present()

        def _connect_explorer(self, image: ImageCandidate, partition: str) -> None:
            if self.explorer_pending or self.explorer_sessions:
                return
            self.explorer_pending = True
            def work() -> None:
                try:
                    request = ExplorerRequest(
                        uuid4().hex, "connect", str(getattr(self.model, "repository")),
                        image.name, image_fingerprint(image.path), partition,
                    )
                    result = self.explorer.connect(request)
                    if result.status != "ok" or not result.mountpoint or not result.session_id:
                        raise RuntimeError(result.detail)
                    GLib.idle_add(self._explorer_connected, result)
                except Exception as error:
                    GLib.idle_add(self._explorer_connect_failed, str(error))
            threading.Thread(target=work, name="transume-explorer-connect", daemon=True).start()

        def _explorer_connected(self, result: Any) -> bool:
            self.explorer_pending = False
            self.explorer_sessions.add(result.session_id)
            dialog = Gtk.Dialog(transient_for=self.get_root(), modal=True, title=_("Image files mounted"))
            dialog.set_default_size(520, 1)
            content = dialog.get_content_area()
            content.set_spacing(16)
            content.set_margin_top(18); content.set_margin_bottom(16)
            content.set_margin_start(18); content.set_margin_end(18)
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, css_classes=["info-card"])
            card.append(Gtk.Label(label=_("Image files are ready"), xalign=0, css_classes=["card-title"]))
            card.append(Gtk.Label(label=_("The image is mounted read-only. Open it in the file manager, or unmount it when finished."), xalign=0, wrap=True, css_classes=["muted"]))
            mountpoint = Gtk.Label(label=result.mountpoint, xalign=0, wrap=True, selectable=True, css_classes=["command-preview"])
            mountpoint.set_wrap_mode(Pango.WrapMode.CHAR)
            card.append(mountpoint)
            status = Gtk.Label(xalign=0, wrap=True, css_classes=["warning-text"])
            status.set_visible(False)
            card.append(status)
            content.append(card)
            actions = Gtk.Box(spacing=8, halign=Gtk.Align.END, css_classes=["dialog-actions"])
            unmount = Gtk.Button(label=_("Unmount"))
            open_files = Gtk.Button(label=_("Open files"), css_classes=["suggested-action"])
            actions.append(unmount); actions.append(open_files); content.append(actions)
            dialog.explorer_status = status
            dialog.explorer_actions = actions
            def open_location(_button: Gtk.Button) -> None:
                try: Gio.AppInfo.launch_default_for_uri(Path(result.mountpoint).as_uri(), None)
                except Exception as error: self._dialog(_("Explorer action failed"), str(error))
            def disconnect(_button: Gtk.Button) -> None:
                actions.set_sensitive(False)
                status.set_label(_("Unmounting image files...")); status.set_visible(True)
                def work() -> None:
                    try:
                        disconnected = self.explorer.disconnect(uuid4().hex, result.session_id)
                        if disconnected.status not in {"ok", "not-mounted"}:
                            raise RuntimeError(disconnected.detail)
                        GLib.idle_add(self._explorer_disconnected, dialog, result.session_id)
                    except Exception as error:
                        GLib.idle_add(self._explorer_disconnect_failed, dialog, str(error))
                threading.Thread(target=work, name="transume-explorer-disconnect", daemon=True).start()
            open_files.connect("clicked", open_location)
            unmount.connect("clicked", disconnect)
            dialog.present(); return GLib.SOURCE_REMOVE

        def _explorer_connect_failed(self, detail: str) -> bool:
            self.explorer_pending = False
            self._dialog(_("Could not explore image"), detail)
            self._render()
            return GLib.SOURCE_REMOVE

        def _explorer_disconnected(self, dialog: Gtk.Dialog, session: str) -> bool:
            self.explorer_sessions.discard(session); dialog.destroy(); return GLib.SOURCE_REMOVE

        def _explorer_disconnect_failed(self, dialog: Gtk.Dialog, detail: str) -> bool:
            dialog.explorer_actions.set_sensitive(True)
            dialog.explorer_status.set_label(_("Could not unmount image files: {detail}").format(detail=detail))
            dialog.explorer_status.set_visible(True)
            return GLib.SOURCE_REMOVE

        def cleanup_explorer(self) -> tuple[str, ...]:
            errors = []
            for session in tuple(self.explorer_sessions):
                try:
                    result = self.explorer.disconnect(uuid4().hex, session)
                    if result.status not in {"ok", "not-mounted"}:
                        raise RuntimeError(result.detail)
                    self.explorer_sessions.discard(session)
                except Exception as error: errors.append(str(error))
            return tuple(errors)

        def _rename(self, image: ImageCandidate, refresh: Callable[[], None] | None = None) -> None:
            dialog = Gtk.Dialog(transient_for=self.get_root(), modal=True, title=_("Rename image"))
            dialog.set_default_size(460, 1)
            content = dialog.get_content_area()
            content.set_spacing(16)
            content.set_margin_top(18); content.set_margin_bottom(16)
            content.set_margin_start(18); content.set_margin_end(18)
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, css_classes=["info-card"])
            card.append(Gtk.Label(label=_("Choose a new image name"), xalign=0, css_classes=["card-title"]))
            card.append(Gtk.Label(label=_("Use letters, digits, dots, underscores, or hyphens. The image data will not be changed."), xalign=0, wrap=True, css_classes=["muted"]))
            name = Gtk.Entry(text=image.name, placeholder_text=_("Safe image name"))
            name.set_activates_default(True)
            set_accessible_label(name, _("New image name"))
            card.append(name); content.append(card)
            actions = Gtk.Box(spacing=8, halign=Gtk.Align.END, css_classes=["dialog-actions"])
            cancel = Gtk.Button(label=_("Cancel")); rename = Gtk.Button(label=_("Rename"), css_classes=["suggested-action"])
            cancel.connect("clicked", lambda _button: dialog.destroy())
            def apply_name(_button: Gtk.Button) -> None:
                try:
                    self.model.rename_image(image, name.get_text())
                    (refresh or self._render)()
                    dialog.destroy()
                except Exception as error: self._dialog(_("Could not rename image"), str(error))
            rename.connect("clicked", apply_name)
            name.connect("activate", lambda _entry: rename.emit("clicked"))
            actions.append(cancel); actions.append(rename); content.append(actions)
            dialog.present()

        def _delete(self, image: ImageCandidate, refresh: Callable[[], None] | None = None) -> None:
            dialog = Gtk.Dialog(transient_for=self.get_root(), modal=True, title=_("Delete image"))
            dialog.set_default_size(480, 1)
            content = dialog.get_content_area()
            content.set_spacing(16)
            content.set_margin_top(18); content.set_margin_bottom(16)
            content.set_margin_start(18); content.set_margin_end(18)
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, css_classes=["info-card", "destructive-zone"])
            card.append(Gtk.Label(label=_("Delete this image?"), xalign=0, css_classes=["card-title"])
            )
            card.append(Gtk.Label(label=_("Type {name} to move this image to protected trash and delete it.").format(name=image.name), xalign=0, wrap=True))
            confirm = Gtk.Entry(placeholder_text=image.name); card.append(confirm); content.append(card)
            actions = Gtk.Box(spacing=8, halign=Gtk.Align.END, css_classes=["dialog-actions"])
            cancel = Gtk.Button(label=_("Cancel")); delete = Gtk.Button(label=_("Delete"), css_classes=["destructive-action"])
            delete.set_sensitive(False)
            confirm.connect("changed", lambda entry: delete.set_sensitive(entry.get_text() == image.name))
            cancel.connect("clicked", lambda _button: dialog.destroy())
            def apply_delete(_button: Gtk.Button) -> None:
                try:
                    self.model.delete_image(image, confirm.get_text())
                    (refresh or self._render)()
                    dialog.destroy()
                except Exception as error:
                    recovery = getattr(error, "recovery_path", None)
                    self._dialog(_("Could not fully delete image"), _("{error}{recovery}").format(error=error, recovery=_("\nRecovery path: {path}").format(path=recovery) if recovery else ""))
            delete.connect("clicked", apply_delete)
            actions.append(cancel); actions.append(delete); content.append(actions)
            dialog.present()

        def _action(self, action: str, image: ImageCandidate) -> None:
            try:
                self.review(build_image_action(action, image), {"source": image.name, "destination": "Image integrity"})
            except ValueError as error:
                self._dialog(_("Operation is not ready"), str(error))



    class ReviewPage(Gtk.Box):
        __gtype_name__ = "TransumeReviewPage"

        def __init__(self, operation: str, selection: dict[str, str], command: str,
                     destination_serial: str | None, risk: str, start_job: Callable[[], None],
                     spec: Any | None = None, warnings: tuple[str, ...] = ()) -> None:
            super().__init__(orientation=Gtk.Orientation.VERTICAL)
            scroll = Gtk.ScrolledWindow(
                hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True,
            )
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
            body.add_css_class("page")
            body.append(page_heading(_("Review before start"), _("Confirm the route and consequences. Nothing has been changed yet.")))
            summary = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            summary.add_css_class("info-card")
            summary.append(Gtk.Label(label=_("{operation} route").format(operation=operation.title()), xalign=0, css_classes=["card-title"]))
            summary.append(Gtk.Label(label=_("Source: {source}").format(source=selection.get("source", _("Not selected"))), xalign=0, wrap=True))
            summary.append(Gtk.Label(label=_("Destination: {destination}").format(destination=selection.get("destination", _("Not selected"))), xalign=0, wrap=True))
            if spec is not None:
                summary.append(Gtk.Label(label=_("Image name: {name}").format(name=spec.image_name or _("Not applicable")), xalign=0, wrap=True))
                summary.append(Gtk.Label(label=_("Post action: {action}").format(action=spec.post_action), xalign=0, wrap=True))
                if spec.destinations:
                    mapping = ", ".join(device.path for device in spec.destinations)
                    summary.append(Gtk.Label(label=_("Target mapping: {mapping}").format(mapping=mapping), xalign=0, wrap=True))
                options = Gtk.Grid(column_spacing=16, row_spacing=4)
                for row, (name, value) in enumerate(spec.options.items()):
                    options.attach(Gtk.Label(label=name.replace("_", " ").title(), xalign=0), 0, row, 1, 1)
                    options.attach(Gtk.Label(label=str(value), xalign=0), 1, row, 1, 1)
                if spec.options:
                    summary.append(Gtk.Label(label=_("Selected options"), xalign=0, css_classes=["setting-label"]))
                    summary.append(options)
            body.append(summary)
            if risk == "destructive":
                warning = Gtk.Label(label=_("Warning: all data on the destination drive will be overwritten."), xalign=0, wrap=True)
                warning.add_css_class("danger-banner")
                set_accessible_label(warning, _("Destructive operation warning. All destination data will be overwritten."))
                body.append(warning)
            checks = Gtk.Label(label=_("Preflight checks\n• Device identities will be verified again\n• Mounts and available space will be checked\n• Authorization is requested only when starting"), xalign=0)
            checks.add_css_class("info-card")
            body.append(checks)
            for message in warnings:
                warning = Gtk.Label(label=_(message), xalign=0, wrap=True)
                warning.add_css_class("warning-text")
                body.append(warning)
            automation = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            automation.add_css_class("info-card")
            automation_header = Gtk.Box(spacing=12)
            automation_header.append(Gtk.Label(
                label=_("Automation"), xalign=0, hexpand=True,
                css_classes=["card-title"],
            ))
            automation.append(automation_header)
            automation.append(Gtk.Label(
                label=_(
                    "You can run this Clonezilla command separately as root for "
                    "automation. Direct execution bypasses Transume preflight, "
                    "device identity revalidation, and PolicyKit safeguards."
                ),
                xalign=0, wrap=True, css_classes=["muted"],
            ))
            command_label = Gtk.Label(label=command, xalign=0, wrap=True, selectable=True)
            command_label.add_css_class("command-preview")
            set_accessible_label(command_label, _("Validated Clonezilla command preview"))
            command_overlay = Gtk.Overlay()
            command_overlay.add_css_class("command-view")
            command_overlay.set_child(command_label)
            copy_command = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
            copy_command.add_css_class("overlay-copy-button")
            copy_command.set_halign(Gtk.Align.END)
            copy_command.set_valign(Gtk.Align.START)
            copy_command.set_tooltip_text(_("Copy command"))
            set_accessible_label(copy_command, _("Copy command"))
            copy_command.connect(
                "clicked", lambda _button: self.get_clipboard().set_text(command)
            )
            command_overlay.add_overlay(copy_command)
            automation.append(command_overlay)
            body.append(automation)
            start = Gtk.Button(label=_("Start {operation}").format(operation=operation))
            start.add_css_class("suggested-action")
            if risk == "destructive":
                multiple_targets = bool(destination_serial and "," in destination_serial)
                suffix = "" if multiple_targets else (destination_serial or "")[-4:]
                confirmation = Gtk.Entry(
                    placeholder_text=(_("Type destination serial suffix {suffix}").format(suffix=suffix) if suffix else _("Type START to confirm all targets")),
                    input_purpose=Gtk.InputPurpose.FREE_FORM,
                )
                set_accessible_label(confirmation, _("Confirm destination by typing serial suffix {suffix}").format(suffix=suffix) if suffix else _("Type START to confirm all destructive targets"))
                start.set_sensitive(False)
                confirmation.connect(
                    "changed",
                    lambda entry: start.set_sensitive(entry.get_text() == (suffix or "START")),
                )
                body.append(confirmation)
            start.connect("clicked", lambda _button: start_job())
            scroll.set_child(body)
            self.append(scroll)

            bar = Gtk.Box(spacing=12)
            bar.add_css_class("action-bar")
            status = Gtk.Box(spacing=7)
            status.add_css_class("ready-status")
            status.append(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
            status.append(Gtk.Label(label=_("Nothing has been changed yet")))
            bar.append(status)
            bar.append(Gtk.Box(hexpand=True))
            bar.append(start)
            self.append(bar)


    class ActivityPage(Gtk.ScrolledWindow):
        __gtype_name__ = "TransumeActivityPage"

        def __init__(self, model: Any) -> None:
            super().__init__(hscrollbar_policy=Gtk.PolicyType.NEVER)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
            body.add_css_class("page")
            body.append(page_heading(_("Activity"), _("Current work, recent results, and redacted logs.")))
            current = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            current.add_css_class("info-card")
            self.idle_state = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.idle_state.add_css_class("activity-empty")
            idle_icon = Gtk.Image.new_from_icon_name("view-list-symbolic")
            idle_icon.set_pixel_size(32)
            self.idle_state.append(idle_icon)
            self.idle_state.append(Gtk.Label(
                label=_("No operation is running"), css_classes=["card-title"],
            ))
            self.idle_state.append(Gtk.Label(
                label=_("Start a backup, restore, or clone operation to see its progress here."),
                wrap=True, justify=Gtk.Justification.CENTER, css_classes=["muted"],
            ))
            current.append(self.idle_state)
            self.active_state = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.active_state.set_visible(False)
            status_row = Gtk.Box(spacing=12)
            self.status = Gtk.Label(
                label=_("Operation is starting"), xalign=0, hexpand=True,
                css_classes=["card-title"],
            )
            status_row.append(self.status)
            self.cancel = Gtk.Button(label=_("Cancel"))
            self.cancel.set_sensitive(False)
            self.cancel.connect("clicked", lambda _button: self._cancel())
            status_row.append(self.cancel)
            self.active_state.append(status_row)
            self.progress = Gtk.ProgressBar(show_text=True, text=_("Preparing"))
            set_accessible_label(self.progress, _("Current operation progress: preparing"))
            self.active_state.append(self.progress)
            self.stage = Gtk.Label(label=_("Preparing operation"), xalign=0, wrap=True)
            self.active_state.append(self.stage)
            self.metrics = Gtk.Label(label="", xalign=0)
            set_accessible_label(self.metrics, _("Operation timing and transfer status"))
            self.active_state.append(self.metrics)
            self.warning = Gtk.Label(label="", xalign=0, wrap=True)
            self.warning.add_css_class("warning-text")
            self.warning.set_visible(False)
            self.active_state.append(self.warning)
            self._samples: list[tuple[float, float]] = []
            self._started = 0.0
            self._timer = 0
            self._log_lines: list[str] = []
            self.log = Gtk.Label(label="", xalign=0, selectable=True)
            self.log.set_valign(Gtk.Align.START)
            self.log.set_visible(False)
            self.log_scroll = Gtk.ScrolledWindow(
                hscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
                vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
                vexpand=True,
                min_content_height=220,
            )
            self.log_scroll.add_css_class("command-preview")
            self.log_scroll.set_child(self.log)
            self.log_overlay = Gtk.Overlay()
            self.log_overlay.add_css_class("log-view")
            self.log_overlay.set_child(self.log_scroll)
            self.log_overlay.set_visible(False)
            self.copy_log = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
            self.copy_log.add_css_class("overlay-copy-button")
            self.copy_log.add_css_class("flat")
            self.copy_log.set_halign(Gtk.Align.END)
            self.copy_log.set_valign(Gtk.Align.START)
            self.copy_log.set_tooltip_text(_("Copy the complete operation log"))
            set_accessible_label(self.copy_log, _("Copy operation log"))
            self.copy_log.set_sensitive(False)
            self.copy_log.connect("clicked", self._copy_log)
            self.log_overlay.add_overlay(self.copy_log)
            self.active_state.append(self.log_overlay)
            self.open_current_log = Gtk.Button(label=_("Open log"))
            self.open_current_log.set_sensitive(False)
            self.open_current_log.connect("clicked", lambda _button: self._open_log(self._current_record))
            self.active_state.append(self.open_current_log)
            current.append(self.active_state)
            self._current_record = None
            body.append(current)
            self.model = model
            self.history_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            body.append(self.history_box)
            self._render_history()
            self.set_child(body)

        def _render_history(self) -> None:
            while child := self.history_box.get_first_child():
                self.history_box.remove(child)
            history, error = _call_model(self.model, "list_activity")
            if error:
                self.history_box.append(Gtk.Label(label=error, xalign=0, wrap=True, css_classes=["danger-banner"]))
            if not history:
                self.history_box.append(Gtk.Label(label=_("No completed operations yet."), xalign=0, css_classes=["empty-state"]))
                return
            header = Gtk.Box(spacing=8)
            header.append(Gtk.Label(label=_("{count} recent operation(s)").format(count=len(history)), xalign=0, hexpand=True, css_classes=["card-title"]))
            clear = Gtk.Button(label=_("Clear history"))
            clear.connect("clicked", self._clear_history)
            header.append(clear)
            self.history_box.append(header)
            for record in reversed(history):
                status = record.status or "running"
                finished = record.finished_at.strftime("%Y-%m-%d %H:%M UTC") if record.finished_at else _("Running")
                duration = _("Running") if record.finished_at is None else str(record.finished_at - record.started_at).split(".", 1)[0]
                exit_code = _("Unknown") if record.exit_code is None else str(record.exit_code)
                labels = ", ".join(record.affected_labels or (record.source_label, record.destination_label))
                card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, css_classes=["info-card"])
                card.append(Gtk.Label(label=_("{operation} | {status} | {finished} | Duration {duration}\nExit code: {exit_code}  Affected: {labels}\nVerification: {verification}  Cleanup: {cleanup}\n{detail}").format(operation=record.operation.title(), status=status.title(), finished=finished, duration=duration, exit_code=exit_code, labels=labels, verification=record.verification or _("Unknown"), cleanup=record.cleanup or _("Unknown"), detail=record.detail), xalign=0, wrap=True))
                path = getattr(self.model, "log_path", lambda _record: None)(record)
                if path is not None:
                    open_log = Gtk.Button(label=_("Open log"))
                    open_log.connect("clicked", lambda _button, item=record: self._open_log(item))
                    card.append(open_log)
                self.history_box.append(card)

        def _clear_history(self, _button: Gtk.Button) -> None:
            dialog, content = dialog_shell(
                self.get_root(), _("Clear activity history?"),
                _("Recent operation results will be permanently removed."),
                icon_name="user-trash-symbolic",
            )
            actions = dialog_actions(content)
            cancel = Gtk.Button(label=_("Cancel"))
            clear_button = Gtk.Button(label=_("Clear history"), css_classes=["destructive-action"])
            cancel.connect("clicked", lambda _button: dialog.destroy())
            def clear_history(_button: Gtk.Button) -> None:
                clear = getattr(self.model, "clear_activity", None)
                if callable(clear):
                    clear()
                self._render_history()
                dialog.destroy()
            clear_button.connect("clicked", clear_history)
            actions.append(cancel)
            actions.append(clear_button)
            dialog.present()

        def begin(self, operation: str, cancel: Callable[[], None]) -> None:
            self._cancel_job = cancel
            self.idle_state.set_visible(False)
            self.active_state.set_visible(True)
            self.status.set_label(_("{operation} is running").format(operation=operation.title()))
            self.cancel.set_sensitive(True)
            self.progress.set_fraction(0)
            self.progress.set_text(_("Preparing"))
            self.warning.set_label("")
            self.warning.set_visible(False)
            self._samples = []
            self._started = time.monotonic()
            if self._timer:
                GLib.source_remove(self._timer)
            self._timer = GLib.timeout_add(1000, self._update_metrics)
            self._log_lines.clear()
            self.log.set_label("")
            self.copy_log.set_sensitive(False)
            self.open_current_log.set_sensitive(False)
            self.log.set_visible(True)
            self.log_overlay.set_visible(True)

        def set_current_record(self, record: Any) -> None:
            self._current_record = record
            self.open_current_log.set_sensitive(record is not None)

        def _cancel(self) -> None:
            self._cancel_job()
            self.cancel.set_sensitive(False)
            self.status.set_label(_("Cancelling operation"))

        def handle_event(self, event: dict[str, Any]) -> None:
            percent = event.get("percent")
            if isinstance(percent, (int, float)):
                self.progress.set_fraction(max(0.0, min(1.0, percent / 100)))
                self.progress.set_text(_("{percent:.1f}%").format(percent=percent))
                set_accessible_label(self.progress, _("Current operation progress: {percent:.1f} percent").format(percent=percent))
                self._samples.append((time.monotonic(), float(percent)))
                self._samples = self._samples[-20:]
            if event.get("kind") in {"stage", "error"}:
                self.stage.set_label(event.get("message", ""))
            elif event.get("kind") == "warning":
                self.warning.set_label(_("Warning: {message}").format(message=event.get("message", "")))
                self.warning.set_visible(True)
                set_accessible_label(self.warning, self.warning.get_label())
            adjustment = self.log_scroll.get_vadjustment()
            follow = (
                adjustment.get_value() + adjustment.get_page_size()
                >= adjustment.get_upper() - 2
            )
            self._log_lines.append(event.get("message", ""))
            del self._log_lines[:-2000]
            self.log.set_label("\n".join(self._log_lines))
            self.copy_log.set_sensitive(True)
            if follow:
                GLib.idle_add(self._scroll_log_to_end)

        def _scroll_log_to_end(self) -> bool:
            adjustment = self.log_scroll.get_vadjustment()
            adjustment.set_value(max(0, adjustment.get_upper() - adjustment.get_page_size()))
            return GLib.SOURCE_REMOVE

        def _copy_log(self, _button: Gtk.Button) -> None:
            clipboard = self.get_clipboard()
            clipboard.set_text("\n".join(self._log_lines))

        def _update_metrics(self) -> bool:
            elapsed, eta = elapsed_and_eta(self._samples, time.monotonic()) if self._samples else (max(0.0, time.monotonic() - self._started), None)
            text = _("Elapsed {minutes}:{seconds:02d}").format(minutes=int(elapsed) // 60, seconds=int(elapsed) % 60)
            if eta is not None:
                text = _("{elapsed}  ETA {minutes}:{seconds:02d}").format(elapsed=text, minutes=int(eta) // 60, seconds=int(eta) % 60)
            self.metrics.set_label(text)
            return GLib.SOURCE_CONTINUE

        def _open_log(self, record: Any) -> None:
            path = getattr(self.model, "log_path", lambda _record: None)(record)
            if path is None:
                return
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = _("Log is unavailable.")
            dialog = Gtk.Dialog(transient_for=self.get_root(), modal=True, title=_("Operation log"))
            dialog.set_default_size(720, 460)
            content = dialog.get_content_area()
            content.set_spacing(16)
            content.set_margin_top(20); content.set_margin_bottom(16)
            content.set_margin_start(20); content.set_margin_end(20)

            header = Gtk.Box(spacing=12)
            icon = Gtk.Image.new_from_icon_name("text-x-generic-symbolic")
            icon.set_pixel_size(32)
            icon.add_css_class("log-dialog-icon")
            header.append(icon)
            heading = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3, hexpand=True)
            heading.append(Gtk.Label(label=_("Operation log"), xalign=0, css_classes=["page-title"]))
            heading.append(Gtk.Label(label=str(path), xalign=0, ellipsize=Pango.EllipsizeMode.MIDDLE,
                                     selectable=True, css_classes=["muted"]))
            header.append(heading)
            content.append(header)

            view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
            view.add_css_class("operation-log")
            view.set_left_margin(14); view.set_right_margin(14)
            view.set_top_margin(12); view.set_bottom_margin(12)
            view.get_buffer().set_text(text)
            scroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=300)
            scroll.add_css_class("log-dialog-view")
            scroll.set_child(view)
            overlay = Gtk.Overlay()
            overlay.add_css_class("log-view")
            overlay.set_child(scroll)
            copy = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
            copy.add_css_class("overlay-copy-button")
            copy.add_css_class("flat")
            copy.set_halign(Gtk.Align.END)
            copy.set_valign(Gtk.Align.START)
            copy.set_tooltip_text(_("Copy the complete operation log"))
            set_accessible_label(copy, _("Copy operation log"))
            copy.connect("clicked", lambda _button: self.get_clipboard().set_text(text))
            overlay.add_overlay(copy)
            content.append(overlay)

            actions = Gtk.Box(halign=Gtk.Align.END, css_classes=["dialog-actions"])
            close = Gtk.Button(label=_("Close"))
            close.add_css_class("suggested-action")
            close.connect("clicked", lambda _button: dialog.destroy())
            actions.append(close)
            content.append(actions)
            dialog.present()

        def finish(self, status: str, detail: str, *, risk: str = "") -> None:
            if self._timer:
                GLib.source_remove(self._timer)
                self._timer = 0
            self.cancel.set_sensitive(False)
            self.status.set_label({"ok": _("Operation completed"), "cancelled": _("Operation cancelled")}.get(status, _("Operation failed")))
            if status == "ok":
                self.progress.set_fraction(1)
                self.progress.set_text(_("Completed"))
            elif status == "cancelled":
                self.progress.set_text(_("Cancelled"))
            else:
                self.progress.set_text(_("Failed"))
            self.stage.set_label(detail)
            if status == "cancelled" and risk == "destructive":
                self.warning.set_label(_("Warning: the destination may be partially written."))
                self.warning.set_visible(True)
            self._render_history()

else:
    class _Unavailable:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            require_gtk()

    HomePage = AboutPage = RouteEditorPage = ImageBrowserPage = ImagesPage = ReviewPage = ActivityPage = _Unavailable
