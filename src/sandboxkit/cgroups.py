# SPDX-License-Identifier: 0BSD
"""cgroup v2 resource limits applied to the sandbox process tree.

The parent creates a leaf cgroup inside the caller's delegated
subtree, enables the needed controllers, writes the limit interface
files and moves the sandbox child in before the payload runs. Only
the unified cgroup v2 hierarchy is supported; v1 setups raise
UnsupportedError.

Rootless reality: migrating a process needs write access to the
target cgroup.procs and to the cgroup.procs of the common ancestor
of source and target, so only cgroups under a writable ancestor of
the caller's own cgroup qualify. A systemd unit started with
Delegate=yes provides one; a plain login session usually does not.

Only the documented core interface files are used: memory.max,
memory.high, pids.max, cpu.max, cpu.weight and io.weight.

Reference: https://docs.kernel.org/admin-guide/cgroup-v2.html
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import _syscall
from .errors import SandboxError, UnsupportedError

__all__ = ["CGroups", "cgroups_supported"]

CGROUP2_SUPER_MAGIC = 0x63677270
"""f_type of a cgroup v2 mount, from linux/magic.h."""

CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_SELF_CGROUP = Path("/proc/self/cgroup")

_FILE_CONTROLLER = {
    "memory.max": "memory",
    "memory.high": "memory",
    "pids.max": "pids",
    "cpu.max": "cpu",
    "cpu.weight": "cpu",
    "io.weight": "io",
}


@dataclass(frozen=True)
class CGroups:
    """cgroup v2 limits for the sandboxed process tree.

    Each field maps to one cgroup v2 interface file; None leaves it
    unwritten. cpu_max is the cpu.max quota/period pair, given either
    as the literal file content ("50000 100000" or "max 100000") or as
    a (quota, period) tuple where quota is an int or "max". cpu_weight
    and io_weight take the kernel range 1..10000 (default 100).
    """

    memory_max: int | None = None  # memory.max, bytes
    memory_high: int | None = None  # memory.high, bytes
    pids_max: int | None = None  # pids.max, count
    cpu_max: str | tuple[str | int, int] | None = None  # cpu.max
    cpu_weight: int | None = None  # cpu.weight, 1..10000
    io_weight: int | None = None  # io.weight, 1..10000

    def __post_init__(self) -> None:
        for name in ("memory_max", "memory_high", "pids_max"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be non-negative")
        for name in ("cpu_weight", "io_weight"):
            value = getattr(self, name)
            if value is not None and not 1 <= value <= 10000:
                raise ValueError(f"{name} must be between 1 and 10000")
        if self.cpu_max is not None:
            _check_cpu_max(self.cpu_max)

    def files(self) -> dict[str, str]:
        """Map each configured field to its interface file content."""
        out: dict[str, str] = {}
        if self.memory_max is not None:
            out["memory.max"] = str(self.memory_max)
        if self.memory_high is not None:
            out["memory.high"] = str(self.memory_high)
        if self.pids_max is not None:
            out["pids.max"] = str(self.pids_max)
        if self.cpu_max is not None:
            if isinstance(self.cpu_max, str):
                out["cpu.max"] = self.cpu_max
            else:
                out["cpu.max"] = f"{self.cpu_max[0]} {self.cpu_max[1]}"
        if self.cpu_weight is not None:
            out["cpu.weight"] = str(self.cpu_weight)
        if self.io_weight is not None:
            out["io.weight"] = str(self.io_weight)
        return out

    def controllers(self) -> set[str]:
        """Controllers the configured files need, e.g. {"memory", "pids"}."""
        return {_FILE_CONTROLLER[name] for name in self.files()}


def _check_cpu_max(value: str | tuple[str | int, int]) -> None:
    text = value if isinstance(value, str) else f"{value[0]} {value[1]}"
    parts = text.split()
    ok = (
        len(parts) == 2
        and (parts[0] == "max" or parts[0].isdigit())
        and parts[1].isdigit()
        and int(parts[1]) > 0
    )
    if not ok:
        raise ValueError(
            'cpu_max must be "QUOTA PERIOD" like "50000 100000" or "max 100000"'
        )


def _v2_mounted(root: Path) -> bool:
    """True when root sits on a cgroup2 filesystem (statfs f_type)."""
    try:
        return _syscall.fsmagic(str(root)) == CGROUP2_SUPER_MAGIC
    except OSError:
        return False


def _current_cgroup(proc_file: Path = PROC_SELF_CGROUP) -> str:
    """The caller's v2 cgroup path relative to the cgroup root."""
    for line in proc_file.read_text().splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise UnsupportedError(errno.EOPNOTSUPP, "no cgroup v2 entry found")


def _delegated_dir(root: Path, rel: str) -> Path | None:
    """Deepest cgroup on the caller's own path usable as a parent.

    Creating a leaf needs write access on the directory; migrating a
    process into it needs write access on its cgroup.procs, because the
    kernel checks the file on both target and common ancestor.
    """
    path = root.joinpath(rel.lstrip("/"))
    if path != root and root not in path.parents:
        path = root
    while True:
        procs = path / "cgroup.procs"
        if os.access(path, os.W_OK) and os.access(procs, os.W_OK):
            return path
        if path == root:
            return None
        path = path.parent


def cgroups_supported(
    root: Path = CGROUP_ROOT, proc_file: Path = PROC_SELF_CGROUP
) -> bool:
    """Probe whether the caller can create and join a limited cgroup.

    True only on unified cgroup v2 with a writable delegated ancestor
    cgroup, the same path Sandbox takes. False means cgroups= limits
    raise in strict mode or degrade with a warning otherwise.
    """
    if not _v2_mounted(root):
        return False
    try:
        rel = _current_cgroup(proc_file)
    except OSError:
        return False
    return _delegated_dir(root, rel) is not None


class Lease:
    """A created leaf cgroup; cleanup() removes it best effort."""

    __slots__ = ("_path",)

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def attach(self, pid: int) -> None:
        """Move pid into the cgroup; forked descendants inherit it."""
        self._path.joinpath("cgroup.procs").write_text(f"{pid}\n")

    def cleanup(self) -> None:
        """Kill survivors via cgroup.kill (5.14+) and remove the cgroup."""
        with contextlib.suppress(OSError):
            self._path.joinpath("cgroup.kill").write_text("1")
        with contextlib.suppress(OSError):
            self._path.rmdir()


def _word_set(path: Path) -> set[str]:
    try:
        return set(path.read_text().split())
    except OSError:
        return set()


def create(
    cfg: CGroups,
    *,
    strict: bool,
    root: Path = CGROUP_ROOT,
    proc_file: Path = PROC_SELF_CGROUP,
) -> Lease | None:
    """Create a leaf cgroup, enable controllers and write cfg's limits.

    Returns the lease for the new cgroup. When cgroup support is
    missing entirely, strict raises SandboxError and non-strict warns
    and returns None. Partial failures (a controller the delegation
    does not hand out, a refused limit write) degrade the same way:
    strict raises, non-strict warns and applies the rest.
    """

    def fail(exc: SandboxError) -> None:
        if strict:
            raise exc
        warnings.warn(str(exc), RuntimeWarning, stacklevel=3)

    if not _v2_mounted(root):
        fail(UnsupportedError(errno.EOPNOTSUPP, "cgroup v2 is not mounted"))
        return None
    try:
        rel = _current_cgroup(proc_file)
    except OSError as exc:
        fail(SandboxError(exc.errno or errno.EIO, str(exc)))
        return None
    base = _delegated_dir(root, rel)
    if base is None:
        fail(
            SandboxError(
                errno.EACCES,
                "no writable cgroup v2 delegation on the caller's cgroup path",
            )
        )
        return None
    leaf = base / f"sandboxkit-{os.getpid()}-{secrets.token_hex(3)}"
    try:
        leaf.mkdir()
    except OSError as exc:
        fail(SandboxError(exc.errno or errno.EIO, f"cannot create {leaf}: {exc}"))
        return None
    try:
        _configure(cfg, base, leaf, fail)
    except SandboxError:
        with contextlib.suppress(OSError):
            leaf.rmdir()
        raise
    return Lease(leaf)


def _write(path: Path, text: str) -> int:
    """Write text to path, returning an errno instead of raising."""
    try:
        path.write_text(text)
    except OSError as exc:
        return exc.errno or errno.EIO
    return 0


def _configure(
    cfg: CGroups, base: Path, leaf: Path, fail: Callable[[SandboxError], None]
) -> None:
    """Enable needed controllers on base and write leaf limit files."""
    needed = cfg.controllers()
    available = _word_set(base / "cgroup.controllers")
    missing = needed - available
    if missing:
        fail(
            UnsupportedError(
                errno.EOPNOTSUPP,
                "cgroup controllers unavailable: " + " ".join(sorted(missing)),
            )
        )
        needed -= missing
    enabled = _word_set(base / "cgroup.subtree_control")
    for ctl in sorted(needed - enabled):
        err = _write(base / "cgroup.subtree_control", f"+{ctl}")
        if err:
            fail(SandboxError(err, f"cannot enable {ctl} on {base}"))
            needed.discard(ctl)
    for name, value in cfg.files().items():
        if _FILE_CONTROLLER[name] not in needed:
            continue
        err = _write(leaf / name, value)
        if err:
            fail(SandboxError(err, f"cannot write {name} in {leaf}"))
