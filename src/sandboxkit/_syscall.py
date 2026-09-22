# SPDX-License-Identifier: 0BSD
"""Raw ctypes bindings for unshare(2), mount(2) and sethostname(2).

unshare goes through the libc wrapper when present and falls back to
the raw syscall, x86_64 number 272. All calls go through libc so no
compiler is needed. See namespaces(7) for the CLONE_NEW* flag bits.
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import sys

from .errors import SandboxError, UnsupportedError

SYS_UNSHARE = 272  # x86_64 number for the fallback path

# pivot_root(2) has no glibc wrapper, so the raw syscall is the only
# path. Numbers per arch from the kernel unistd tables.
SYS_PIVOT_ROOT = {
    "x86_64": 155,
    "amd64": 155,
    "aarch64": 41,
    "riscv64": 41,
    "i386": 217,
    "i686": 217,
    "armv6l": 218,
    "armv7l": 218,
}

_libc: ctypes.CDLL | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        if sys.platform != "linux":
            raise UnsupportedError("sandboxkit is only available on Linux")
        name = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(name or None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    return _libc


def _raise(err: int) -> None:
    if err in (errno.ENOSYS, errno.EOPNOTSUPP):
        raise UnsupportedError(err, os.strerror(err))
    raise SandboxError(err, os.strerror(err))


def unshare(flags: int) -> None:
    """Disassociate parts of the process execution context."""
    libc = _get_libc()
    wrapper = getattr(libc, "unshare", None)
    if wrapper is not None:
        ret = int(wrapper(ctypes.c_int(flags)))
    else:
        if platform.machine().lower() not in ("x86_64", "amd64"):
            raise UnsupportedError("no libc unshare wrapper on this architecture")
        ret = int(libc.syscall(SYS_UNSHARE, ctypes.c_int(flags)))
    if ret == -1:
        _raise(ctypes.get_errno())


def mount(
    source: str | None,
    target: str,
    fstype: str | None,
    flags: int = 0,
    data: bytes | None = None,
) -> None:
    """Mount a filesystem. None source or fstype passes NULL to mount(2)."""
    ret = int(
        _get_libc().mount(
            None if source is None else os.fsencode(source),
            os.fsencode(target),
            None if fstype is None else os.fsencode(fstype),
            ctypes.c_ulong(flags),
            data,
        )
    )
    if ret == -1:
        _raise(ctypes.get_errno())


def umount2(target: str, flags: int = 0) -> None:
    """Unmount a filesystem, see umount2(2) for the flag values."""
    ret = int(_get_libc().umount2(os.fsencode(target), ctypes.c_int(flags)))
    if ret == -1:
        _raise(ctypes.get_errno())


def pivot_root(new_root: str, put_old: str) -> None:
    """Change the root mount, see pivot_root(2).

    glibc ships no wrapper, so this goes through libc.syscall with a
    per-arch number table, same pattern as the unshare fallback.
    """
    libc = _get_libc()
    wrapper = getattr(libc, "pivot_root", None)
    if wrapper is not None:
        ret = int(wrapper(os.fsencode(new_root), os.fsencode(put_old)))
    else:
        nr = SYS_PIVOT_ROOT.get(platform.machine().lower())
        if nr is None:
            raise UnsupportedError("no pivot_root syscall number on this architecture")
        ret = int(libc.syscall(nr, os.fsencode(new_root), os.fsencode(put_old)))
    if ret == -1:
        _raise(ctypes.get_errno())


def fsmagic(path: str) -> int:
    """Return the statfs(2) f_type magic of the filesystem hosting path.

    struct statfs is about 120 bytes on every arch and f_type is its
    first __fsword_t field, so a generously sized buffer is safe.
    """
    buf = ctypes.create_string_buffer(512)
    ret = int(_get_libc().statfs(os.fsencode(path), buf))
    if ret == -1:
        _raise(ctypes.get_errno())
    return int.from_bytes(buf.raw[: ctypes.sizeof(ctypes.c_long)], sys.byteorder)


def sethostname(name: str) -> None:
    """Set the hostname of the current UTS namespace."""
    buf = os.fsencode(name)
    ret = int(_get_libc().sethostname(buf, len(buf)))
    if ret == -1:
        _raise(ctypes.get_errno())
