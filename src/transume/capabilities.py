"""Conservative runtime capability probing for Clonezilla."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class ClonezillaCapabilities:
    version: str | None
    binaries: frozenset[str]
    modes: frozenset[str]
    compressors: frozenset[str]
    partclone_version: str | None = None

    def supports(self, capability: str) -> bool:
        return capability in self.binaries or capability in self.modes or capability in self.compressors


def probe_clonezilla(*, which: Callable[[str], str | None] | None = None,
                     run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> ClonezillaCapabilities:
    if which is None:
        which = lambda name: shutil.which(
            name, path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )
    names = (
        "ocs-sr", "ocs-onthefly", "ocs-chkimg", "partclone", "partclone.ext4", "partclone.dd", "partimage",
        "ntfsclone", "dd", "gzip", "pigz", "zstd", "zstdmt", "bzip2",
        "pbzip2", "xz", "pixz", "lzma", "lz4", "lz4mt", "lzop", "lzip", "plzip",
        "lrzip", "lvm", "mount.ecryptfs", "ecryptfs-add-passphrase", "sshfs", "setfacl", "partclone-nbd", "nbdkit", "nbd-client", "blockdev",
    )
    found = {name: which(name) for name in names}
    binary_names = {name for name, path in found.items() if path}
    # Debian provides filesystem-specific executables; Clonezilla chooses one.
    if found["partclone.ext4"] or found["partclone.dd"]:
        binary_names.add("partclone")
    binaries = frozenset(binary_names)
    version = None
    partclone_version = None
    modes: set[str] = set()
    path = found["ocs-sr"]
    if path:
        try:
            result = run(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "clonezilla"], capture_output=True, text=True,
                          timeout=5, check=False, env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
            match = re.search(r"\d+(?:\.\d+)+(?:[-\w.]*)?", result.stdout + result.stderr)
            version = match.group(0) if match else None
        except (OSError, subprocess.SubprocessError):
            pass
        modes.update(("savedisk", "saveparts", "restoredisk", "restoreparts"))
        # The minimum supported Clonezilla provides the native -enc/-pfe contract;
        # runtime availability depends on the eCryptfs helpers, not an exact version.
        if found["mount.ecryptfs"] and found["ecryptfs-add-passphrase"]:
            modes.add("ecryptfs")
    if "partclone" in binary_names:
        try:
            result = run(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "partclone"], capture_output=True, text=True,
                         timeout=5, check=False, env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
            match = re.search(r"\d+(?:\.\d+)+(?:[-+~:\w.]*)?", result.stdout + result.stderr)
            partclone_version = match.group(0) if match else None
        except (OSError, subprocess.SubprocessError):
            pass
    if found["ocs-onthefly"]:
        modes.update(("clone-disk", "clone-part"))
    if found["ocs-chkimg"]:
        modes.add("check-image")
    if found["lvm"]:
        modes.add("lvm2")
    compressors = frozenset(binaries & {
        "gzip", "pigz", "zstd", "zstdmt", "bzip2", "pbzip2", "xz", "pixz", "lzma",
        "lz4", "lz4mt", "lzop", "lzip", "plzip", "lrzip",
    })
    return ClonezillaCapabilities(version, binaries, frozenset(modes), compressors, partclone_version)
