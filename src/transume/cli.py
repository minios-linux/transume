"""Declarative, shell-free automation interface for Transume jobs."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .capabilities import ClonezillaCapabilities, probe_clonezilla
from .client import ClientResult, run_spec
from .clonezilla import build_command
from .domain import DeviceIdentity, JobOperation, PublicJobSpec
from .inventory import BlockDevice, scan_block_devices
from .protocol import redact_text

MAX_INPUT_BYTES = 1_048_576
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_VALIDATION = 3
EXIT_EXECUTION = 4
EXIT_REFUSED = 5
_SECRET_WORDS = ("password", "passphrase", "token", "private_key", "secret")


class CliError(ValueError):
    """An input or preflight error safe to report to an automation caller."""


def _read_input(name: str) -> bytes:
    if name == "-":
        value = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(value) > MAX_INPUT_BYTES:
            raise CliError("input exceeds 1048576 bytes")
        return value
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise CliError("input must be a readable regular non-symlink file") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CliError("input must be a regular file")
        if info.st_size > MAX_INPUT_BYTES:
            raise CliError("input exceeds 1048576 bytes")
        chunks = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > MAX_INPUT_BYTES:
            raise CliError("input exceeds 1048576 bytes")
        return value
    finally:
        os.close(fd)


def _reject_secrets(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CliError("JSON object keys must be strings")
            if any(word in key.lower() for word in _SECRET_WORDS):
                raise CliError("secrets are not accepted in CLI JSON")
            _reject_secrets(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secrets(child)


def _load_json(name: str) -> dict[str, Any]:
    try:
        value = json.loads(_read_input(name).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError("input must be a UTF-8 JSON object") from exc
    if not isinstance(value, dict):
        raise CliError("input must be a JSON object")
    _reject_secrets(value)
    return value


def _devices() -> tuple[BlockDevice, ...]:
    result = []
    def add(device: BlockDevice) -> None:
        result.append(device)
        for child in device.children:
            add(child)
    for device in scan_block_devices():
        add(device)
    return tuple(result)


def _selector_identity(value: Mapping[str, Any], devices: Sequence[BlockDevice]) -> DeviceIdentity:
    allowed = {"serial", "wwn", "by_id"}
    if set(value) - allowed or not set(value) or len(value) != 1:
        raise CliError("device selector requires exactly one of serial, wwn, or by_id")
    field, stable_value = next(iter(value.items()))
    if (not isinstance(stable_value, str) or not stable_value
            or (field != "by_id" and stable_value.startswith("/dev/"))
            or (field == "by_id" and not stable_value.startswith("/dev/disk/by-id/"))):
        raise CliError("device selector must use a non-empty stable identifier")
    matches = []
    for device in devices:
        try:
            identity = device.identity()
        except ValueError:
            continue
        current = getattr(identity, field)
        if (field == "by_id" and stable_value in current) or current == stable_value:
            matches.append(identity)
    if len(matches) != 1:
        raise CliError("device selector must resolve to exactly one current device")
    return matches[0]


def _parse_spec(value: dict[str, Any], *, resolve_selectors: bool = False) -> PublicJobSpec:
    if resolve_selectors:
        devices = _devices()
        value = dict(value)
        for field in ("sources", "destinations"):
            entries = value.get(field)
            if not isinstance(entries, list):
                raise CliError(f"{field} must be a list")
            converted = []
            for entry in entries:
                if not isinstance(entry, Mapping):
                    raise CliError("device selectors must be objects")
                if set(entry) <= {"serial", "wwn", "by_id"}:
                    converted.append(_selector_identity(entry, devices).to_dict())
                else:
                    converted.append(entry)
            value[field] = converted
    try:
        return PublicJobSpec.from_dict(value)
    except (KeyError, TypeError, ValueError) as exc:
        raise CliError(f"invalid PublicJobSpec: {exc}") from exc


def _validate_paths(spec: PublicJobSpec) -> None:
    if spec.repository is None:
        return
    repository = Path(spec.repository)
    try:
        canonical_repository = repository.resolve(strict=True)
    except OSError as exc:
        raise CliError("repository must exist") from exc
    if not canonical_repository.is_dir():
        raise CliError("repository must be a directory")
    if spec.image_name is not None:
        image = canonical_repository / spec.image_name
        # An image name is constrained by build_command; existing input images must
        # resolve inside the current repository rather than through a symlink.
        input_operations = {JobOperation.RESTOREDISK, JobOperation.RESTOREPARTS,
                             JobOperation.CHECK_IMAGE}
        if spec.operation in input_operations:
            try:
                canonical_image = image.resolve(strict=True)
            except OSError as exc:
                raise CliError("image must exist in repository") from exc
            if canonical_repository not in canonical_image.parents:
                raise CliError("image escapes repository")


def _validate_identities(spec: PublicJobSpec, devices: Sequence[BlockDevice]) -> None:
    current: dict[str, tuple[BlockDevice, DeviceIdentity]] = {}
    for device in devices:
        try:
            current[device.path] = (device, device.identity())
        except ValueError:
            continue
    for expected in spec.sources:
        item = current.get(expected.path)
        if item is None or item[1] != expected or not item[0].selectable_source:
            raise CliError(f"source identity is not a current selectable device: {expected.path}")
    for expected in spec.destinations:
        item = current.get(expected.path)
        if item is None or item[1] != expected or not item[0].selectable_destination:
            raise CliError(f"destination identity is not a current selectable device: {expected.path}")


def validate_spec(spec: PublicJobSpec, *, capabilities: ClonezillaCapabilities | None = None,
                  devices: Sequence[BlockDevice] | None = None) -> tuple[str, ...]:
    """Perform automation preflight and return the shell-free command argv."""
    try:
        command = build_command(spec)
    except ValueError as exc:
        raise CliError(f"invalid job command: {exc}") from exc
    _validate_paths(spec)
    if spec.sources or spec.destinations:
        _validate_identities(spec, _devices() if devices is None else devices)
    capabilities = probe_clonezilla() if capabilities is None else capabilities
    missing = [name for name in spec.required_capabilities if not capabilities.supports(name)]
    binary = Path(command.argv[0]).name
    if binary not in capabilities.binaries:
        missing.append(binary)
    if missing:
        raise CliError("required runtime capabilities are unavailable: " + ", ".join(sorted(set(missing))))
    return command.argv


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): ("***" if any(word in str(key).lower() for word in _SECRET_WORDS) else _redact(child))
                for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(child) for child in value]
    return redact_text(value) if isinstance(value, str) else value


def _write_json(value: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(_redact(value), sort_keys=True, separators=(",", ":")) + "\n")


def _atomic_export(path: str, spec: PublicJobSpec) -> None:
    # A public spec deliberately contains no secrets, so export must preserve its
    # stable identifiers rather than producing an unusable redacted job.
    payload = (json.dumps(spec.to_dict(), sort_keys=True, indent=2) + "\n").encode()
    if path == "-":
        sys.stdout.buffer.write(payload)
        return
    destination = Path(path)
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir():
        raise CliError("export parent must be a directory")
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, destination)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None, *, runner: Callable[..., ClientResult] = run_spec) -> int:
    parser = argparse.ArgumentParser(description="Declarative Transume automation")
    parser.add_argument("command", choices=("export", "validate", "dry-run", "execute"))
    parser.add_argument("input", help="PublicJobSpec JSON file, or - for stdin")
    parser.add_argument("--output", default="-", help="export destination (default: stdout)")
    parser.add_argument("--resolve-selectors", action="store_true", help="resolve serial, WWN, or by-id selectors")
    parser.add_argument("--yes", action="store_true", help="confirm a real execute request")
    args = parser.parse_args(argv)
    try:
        value = _load_json(args.input)
        spec = _parse_spec(value, resolve_selectors=args.resolve_selectors)
        if args.command == "export":
            _atomic_export(args.output, spec)
            return EXIT_OK
        command = validate_spec(spec)
        if args.command == "validate":
            _write_json({"status": "valid", "spec": spec.to_dict(redacted=True), "argv": list(command)})
            return EXIT_OK
        if args.command == "execute" and not args.yes:
            raise CliError("execute requires explicit --yes")
        if args.command == "execute" and (spec.options.get("encrypt") is True or spec.options.get("encrypted") is True):
            raise CliError("encrypted job execute requires the interactive UI secret channel")
        result = runner(spec, dry_run=args.command == "dry-run")
        _write_json({"status": result.status, "detail": result.detail, "events": list(result.events)})
        return EXIT_OK if result.status in {"ok", "dry-run"} else EXIT_EXECUTION
    except CliError as exc:
        print(f"transume-cli: {exc}", file=sys.stderr)
        return EXIT_REFUSED if args.command == "execute" and not args.yes else EXIT_VALIDATION
    except (OSError, RuntimeError) as exc:
        print(f"transume-cli: {exc}", file=sys.stderr)
        return EXIT_EXECUTION


if __name__ == "__main__":
    raise SystemExit(main())
