"""Small fail-closed filesystem primitives for image mutations."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
from pathlib import Path


RENAME_NOREPLACE = 1
_SYS_RENAMEAT2 = {"x86_64": 316, "aarch64": 276}.get(platform.machine())
_AT_FDCWD = -100


class NoReplaceUnavailable(OSError):
    """The kernel cannot provide an atomic no-overwrite rename."""


def rename_noreplace(source: Path, target: Path) -> None:
    """Atomically rename a path, refusing to replace any existing target.

    Do not substitute os.rename: its overwrite behavior is unsafe for image data.
    """
    if _SYS_RENAMEAT2 is None:
        raise NoReplaceUnavailable("atomic no-replace rename is unavailable on this platform")
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(_SYS_RENAMEAT2, _AT_FDCWD, os.fsencode(source),
                          _AT_FDCWD, os.fsencode(target), RENAME_NOREPLACE)
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.ENOSYS, errno.EINVAL}:
        raise NoReplaceUnavailable("atomic no-replace rename is unavailable on this kernel")
    raise OSError(error, os.strerror(error), str(source), str(target))
