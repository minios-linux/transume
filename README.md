# Transume

Transume is a GTK4 frontend for Clonezilla on Debian 13 (Trixie), including
the Debian 13-based MiniOS build. Its qualified baseline is Clonezilla
`5.9.9-1` with Partclone `0.3.36+repack-1`; newer compatible versions are
accepted.

The name **Transume** comes from a historical English verb used in the world of
documents. It described making an official copy or extract of a document, and
also attesting that a copy matched its source. Both senses are concerned with
more than mere repetition: they preserve the substance of an original in a new
record.

Transume carries that old idea from documents to disks. It captures not only
files, but also partitions and the structure that makes a system whole, so the
result can be checked, restored, or carried forward onto another drive. The
name is a metaphor for faithful copying, not a claim of legal certification.

Core features are full-disk and partition backup and restore, direct disk and
partition cloning, and image discovery, inspection, and verification. Encrypted
backups use Clonezilla's native eCryptfs mode (`-enc` with a private
`-pfe` file). Encrypted images require their passphrase for restore and cannot
be opened with Image Explorer.

Partition restore can map one explicitly selected image partition to one target
partition. Multiple partitions can be restored together only to corresponding
partition names in the original order. Partition-scoped restore always preserves
the target disk's existing partition table and disk-wide boot metadata.

Clonezilla LVM2 metadata is validated and displayed before restore. Whole-disk
LVM2 backup and restore use Clonezilla's native PV/VG/LV workflow and require
the `lvm2` runtime package.

Repository capacity is checked conservatively before backup. A backup is
rejected before Clonezilla starts when free space is smaller than the combined
source size.

Local folders, removable media, SMB, NFS, and SSH storage can be connected and
selected across backup, restore, and image-management workflows. Connected
storage remains available until it is explicitly disconnected or Transume
closes.

For SSH/SFTP, the first observed host key is pinned in Transume's root-owned
`known_hosts`. Later connections require strict host-key verification, and a
changed key blocks the connection. Passwords and private-key contents are not
persisted by Transume.

## Read-only Image Explorer

The Image Explorer mounts one selected Partclone source partition read-only. It
supports unsuffixed, gzip, and xz payloads, including Clonezilla split payloads.
It requires `partclone-nbd`, `nbdkit`, `nbd-client`, and `setfacl` from `acl`.
Encrypted images and dd/ntfsclone/partimage payloads are not explored. zstd,
lz4, lzma, bzip2, lzip, lzo, lrzip, and unknown compression are visibly
unsupported and are never silently decompressed. The mounted filesystem uses
`ro,nosuid,nodev,noexec`. It remains available until the user selects
`Unmount` or Transume closes.

## Activity logs

Each operation records redacted progress and log events in
`$XDG_STATE_HOME/transume/logs/<job-id>.log` (or
`~/.local/state/transume/logs`). Log directories are mode `0700` and log files
are mode `0600`; logs are bounded to 10 MiB and are removed with cleared or
expired activity history. Job specifications, credentials, full device
identifiers and command previews are never persisted there.

## Declarative automation

`transume-cli` accepts only strict `PublicJobSpec` JSON. It never constructs a
shell command. JSON is read from a regular non-symlink file no larger than 1 MiB
or from stdin (`-`); output JSON is emitted only on stdout and diagnostics only
on stderr. Secrets, passphrases, tokens, and private keys are rejected in CLI
input. Encrypted backup and restore execution require the graphical
application's interactive secret channel.

```sh
transume-cli export job.json --output normalized-job.json
transume-cli validate normalized-job.json
transume-cli dry-run normalized-job.json
transume-cli execute normalized-job.json --yes
```

For portable device selection, use `--resolve-selectors` and put exactly one
stable selector in each source or destination entry, for example
`{"serial":"S3Z..."}` or `{"by_id":"/dev/disk/by-id/wwn-..."}`. It must
resolve to exactly one current device; path-only selectors and ambiguous matches
are rejected. `export` atomically writes output files with mode `0600`.

Exit statuses are stable: `0` success, `2` usage error, `3` invalid input or
validation failure, `4` runner failure, and `5` execute without `--yes`.

## License

Copyright (C) 2026 MiniOS Linux.

Transume is free software licensed under the GNU General Public License,
version 3 or (at your option) any later version. See `LICENSE`.
