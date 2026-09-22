# SPDX-License-Identifier: 0BSD
"""Mount specs applied inside the payload's mount namespace.

Mount describes one mount(2) operation. The bind(), tmpfs(), proc()
and sysfs() constructors cover the common sandbox cases. All mounts
run inside the payload after its mount namespace exists, so the host
mount table is never touched directly. The namespace mounts are made
MS_PRIVATE first: mounts under a shared peer group would otherwise
propagate back to the parent mount namespace.

pivot_root() rotates a caller-prepared directory to / and detaches
the old root.

Flag values come from linux/mount.h, umount flags from sys/mount.h.

References:
https://man7.org/linux/man-pages/man2/mount.2.html
https://man7.org/linux/man-pages/man2/pivot_root.2.html
https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from . import _syscall

__all__ = ["Mount"]

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18

MNT_DETACH = 2


@dataclass(frozen=True)
class Mount:
    """One mount(2) operation for the payload's mount namespace.

    target is the mount point. It must be an absolute path that already
    exists in the filesystem the payload sees. A spec with a source and
    no fstype is a bind mount. recursive makes it an rbind. With fstype
    set it is a filesystem mount and source is its backing device or
    name, defaulting to fstype. readonly, nosuid, nodev and noexec map
    to the MS_* mount flags. options is the filesystem-specific data
    string for mount(2), for example "size=64m" on tmpfs.
    """

    target: str
    source: str | None = None
    fstype: str | None = None
    readonly: bool = False
    recursive: bool = False
    nosuid: bool = False
    nodev: bool = False
    noexec: bool = False
    options: str | None = None

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("target is required")
        if not Path(self.target).is_absolute():
            raise ValueError("target must be an absolute path")
        if self.fstype is None:
            if self.source is None:
                raise ValueError("either fstype or a bind source is required")
        elif self.recursive:
            raise ValueError("recursive applies to bind mounts")

    @property
    def is_bind(self) -> bool:
        """True when this spec is a bind mount (source, no fstype)."""
        return self.fstype is None

    @classmethod
    def bind(
        cls,
        source: str,
        target: str,
        *,
        readonly: bool = False,
        recursive: bool = False,
        nosuid: bool = False,
        nodev: bool = False,
        noexec: bool = False,
    ) -> Mount:
        """Bind-mount source at target, recursively when asked.

        Readonly binds take two mount(2) calls: the kernel ignores
        MS_RDONLY on the bind itself, so apply() remounts with
        MS_BIND|MS_REMOUNT. See mount(2).
        """
        return cls(
            target=target,
            source=source,
            readonly=readonly,
            recursive=recursive,
            nosuid=nosuid,
            nodev=nodev,
            noexec=noexec,
        )

    @classmethod
    def tmpfs(
        cls,
        target: str,
        *,
        size: str = "64m",
        mode: int = 0o777,
        readonly: bool = False,
        nosuid: bool = True,
        nodev: bool = True,
        noexec: bool = False,
    ) -> Mount:
        """Fresh tmpfs at target, bounded to size by default."""
        return cls(
            target=target,
            source="tmpfs",
            fstype="tmpfs",
            readonly=readonly,
            nosuid=nosuid,
            nodev=nodev,
            noexec=noexec,
            options=f"size={size},mode={mode:o}",
        )

    @classmethod
    def proc(
        cls,
        target: str = "/proc",
        *,
        nosuid: bool = True,
        nodev: bool = True,
        noexec: bool = True,
    ) -> Mount:
        """Fresh procfs at target, most useful inside a pid namespace."""
        return cls(
            target=target,
            source="proc",
            fstype="proc",
            nosuid=nosuid,
            nodev=nodev,
            noexec=noexec,
        )

    @classmethod
    def sysfs(
        cls,
        target: str = "/sys",
        *,
        readonly: bool = True,
        nosuid: bool = True,
        nodev: bool = True,
        noexec: bool = True,
    ) -> Mount:
        """Fresh sysfs at target, readonly by default."""
        return cls(
            target=target,
            source="sysfs",
            fstype="sysfs",
            readonly=readonly,
            nosuid=nosuid,
            nodev=nodev,
            noexec=noexec,
        )

    def _flags(self) -> int:
        flags = 0
        if self.readonly:
            flags |= MS_RDONLY
        if self.nosuid:
            flags |= MS_NOSUID
        if self.nodev:
            flags |= MS_NODEV
        if self.noexec:
            flags |= MS_NOEXEC
        return flags

    def apply(self) -> None:
        """Perform the mount in the calling (payload) process.

        Raises OSError with the mount(2) errno on failure. Callers
        treat any failure as fatal to the sandbox.
        """
        data = os.fsencode(self.options) if self.options is not None else None
        flags = self._flags()
        if self.is_bind:
            # mount(2): MS_RDONLY is ignored on the bind itself, so a
            # readonly bind takes a second MS_BIND|MS_REMOUNT call. The
            # remount also pins nosuid/nodev/noexec on kernels that
            # ignore per-mount flags at bind time.
            rec = MS_REC if self.recursive else 0
            _syscall.mount(
                self.source,
                self.target,
                None,
                MS_BIND | rec | (flags & ~MS_RDONLY),
                data,
            )
            if flags:
                _syscall.mount(
                    self.source,
                    self.target,
                    None,
                    MS_BIND | MS_REMOUNT | rec | flags,
                    None,
                )
            return
        _syscall.mount(
            self.source or self.fstype, self.target, self.fstype, flags, data
        )


def make_private(target: str = "/") -> None:
    """Make the mount tree private so mounts cannot propagate out.

    Mounts created under a shared peer group would propagate back to
    the parent mount namespace and leak onto the host, so this runs
    before any sandbox mount.
    """
    _syscall.mount(None, target, None, MS_REC | MS_PRIVATE)


def pivot_root(new_root: str) -> None:
    """Rotate new_root to / and detach the old root, per pivot_root(2).

    new_root is a directory prepared by the caller, typically filled
    with bind Mounts whose targets sit under it. It is bind-mounted
    onto itself to satisfy the mount-point requirement, then the
    pivot_root(".", ".") form stacks the old root underneath so
    umount2(MNT_DETACH) removes it with no scratch directory. See the
    pivot_root(2) NOTES example.
    """
    _syscall.mount(new_root, new_root, None, MS_BIND | MS_REC)
    os.chdir(new_root)
    _syscall.pivot_root(".", ".")
    _syscall.umount2(".", MNT_DETACH)
    os.chdir("/")
