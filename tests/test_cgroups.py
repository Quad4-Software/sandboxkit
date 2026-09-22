# SPDX-License-Identifier: 0BSD
"""Tests for CGroups specs and the cgroup v2 setup path.

The fixture tests build a fake cgroup tree under tmp_path so the
delegation, controller and limit-file logic is exercised without a
writable /sys/fs/cgroup. The pids/memory enforcement tests only run
where a real delegation exists.
"""

import contextlib
import errno
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from sandboxkit import (
    CGroups,
    Namespace,
    Sandbox,
    SandboxError,
    UnsupportedError,
    cgroups,
    cgroups_supported,
)

from .conftest import requires_cgroups


def _fixture(root: Path, rel: str = "/a/b") -> Path:
    """A fake cgroup2 tree with rel as the writable delegated cgroup."""
    base = root / rel.lstrip("/")
    base.mkdir(parents=True)
    (base / "cgroup.controllers").write_text("cpu memory pids\n")
    (base / "cgroup.subtree_control").write_text("")
    (base / "cgroup.procs").write_text("")
    return base


def _proc_file(tmp_path: Path, rel: str = "/a/b") -> Path:
    proc = tmp_path / "self_cgroup"
    proc.write_text(f"0::{rel}\n")
    return proc


def test_cgroups_defaults() -> None:
    cfg = CGroups()
    assert cfg.files() == {}
    assert cfg.controllers() == set()


def test_cgroups_files_and_controllers() -> None:
    cfg = CGroups(
        memory_max=1 << 20,
        memory_high=1 << 19,
        pids_max=8,
        cpu_max="50000 100000",
        cpu_weight=200,
        io_weight=50,
    )
    assert cfg.files() == {
        "memory.max": str(1 << 20),
        "memory.high": str(1 << 19),
        "pids.max": "8",
        "cpu.max": "50000 100000",
        "cpu.weight": "200",
        "io.weight": "50",
    }
    assert cfg.controllers() == {"memory", "pids", "cpu", "io"}


def test_cgroups_cpu_max_tuple() -> None:
    assert CGroups(cpu_max=(50000, 100000)).files()["cpu.max"] == "50000 100000"
    assert CGroups(cpu_max=("max", 100000)).files()["cpu.max"] == "max 100000"


def test_cgroups_rejects_negative() -> None:
    with pytest.raises(ValueError, match="memory_max"):
        CGroups(memory_max=-1)
    with pytest.raises(ValueError, match="pids_max"):
        CGroups(pids_max=-1)


def test_cgroups_weight_range() -> None:
    with pytest.raises(ValueError, match="cpu_weight"):
        CGroups(cpu_weight=0)
    with pytest.raises(ValueError, match="io_weight"):
        CGroups(io_weight=10001)


def test_cgroups_cpu_max_format() -> None:
    for bad in ("50000", "max", "abc 100000", "50000 abc", "50000 0"):
        with pytest.raises(ValueError, match="cpu_max"):
            CGroups(cpu_max=bad)


def test_current_cgroup_parsing(tmp_path: Path) -> None:
    proc = tmp_path / "cgroup"
    proc.write_text("9:freezer:/\n0::/user.slice/x\n")
    assert cgroups._current_cgroup(proc) == "/user.slice/x"


def test_current_cgroup_v1_only(tmp_path: Path) -> None:
    proc = tmp_path / "cgroup"
    proc.write_text("9:freezer:/\n8:memory:/user\n")
    with pytest.raises(UnsupportedError):
        cgroups._current_cgroup(proc)


def test_delegated_dir_deepest_writable(tmp_path: Path) -> None:
    base = _fixture(tmp_path)
    assert cgroups._delegated_dir(tmp_path, "/a/b") == base


def test_delegated_dir_walks_up(tmp_path: Path) -> None:
    base = _fixture(tmp_path)
    (base / "cgroup.procs").chmod(0o444)
    parent = base.parent
    (parent / "cgroup.procs").write_text("")
    assert cgroups._delegated_dir(tmp_path, "/a/b") == parent


def test_delegated_dir_none(tmp_path: Path) -> None:
    base = _fixture(tmp_path)
    (base / "cgroup.procs").chmod(0o444)
    assert cgroups._delegated_dir(tmp_path, "/a/b") is None


def test_cgroups_supported_bool() -> None:
    assert isinstance(cgroups_supported(), bool)


def test_cgroups_supported_not_cgroup2(tmp_path: Path) -> None:
    assert not cgroups_supported(root=tmp_path, proc_file=_proc_file(tmp_path))


def test_create_writes_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = _fixture(tmp_path)
    monkeypatch.setattr(cgroups, "_v2_mounted", lambda _root: True)
    lease = cgroups.create(
        CGroups(pids_max=8),
        strict=True,
        root=tmp_path,
        proc_file=_proc_file(tmp_path),
    )
    assert lease is not None
    assert lease.path.parent == base
    assert (lease.path / "pids.max").read_text() == "8"
    assert (base / "cgroup.subtree_control").read_text() == "+pids"
    lease.attach(os.getpid())
    assert lease.path.joinpath("cgroup.procs").read_text() == f"{os.getpid()}\n"
    lease.cleanup()
    # The kill write landed. rmdir is suppressed because the fixture
    # files are real files, unlike cgroupfs interface files.
    assert (lease.path / "cgroup.kill").read_text() == "1"


def test_create_strict_missing_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _fixture(tmp_path)
    (base / "cgroup.controllers").write_text("cpu pids\n")
    monkeypatch.setattr(cgroups, "_v2_mounted", lambda _root: True)
    with pytest.raises(UnsupportedError, match="memory"):
        cgroups.create(
            CGroups(memory_max=1 << 20),
            strict=True,
            root=tmp_path,
            proc_file=_proc_file(tmp_path),
        )


def test_create_missing_controller_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _fixture(tmp_path)
    (base / "cgroup.controllers").write_text("pids\n")
    monkeypatch.setattr(cgroups, "_v2_mounted", lambda _root: True)
    with pytest.warns(RuntimeWarning, match="memory"):
        lease = cgroups.create(
            CGroups(pids_max=4, memory_max=1 << 20),
            strict=False,
            root=tmp_path,
            proc_file=_proc_file(tmp_path),
        )
    assert lease is not None
    assert (lease.path / "pids.max").read_text() == "4"
    assert not (lease.path / "memory.max").exists()
    lease.cleanup()


def test_create_no_delegation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = _fixture(tmp_path)
    (base / "cgroup.procs").chmod(0o444)
    monkeypatch.setattr(cgroups, "_v2_mounted", lambda _root: True)
    with pytest.raises(SandboxError) as excinfo:
        cgroups.create(
            CGroups(pids_max=4),
            strict=True,
            root=tmp_path,
            proc_file=_proc_file(tmp_path),
        )
    assert excinfo.value.errno == errno.EACCES


def test_sandbox_cgroups_unavailable_strict() -> None:
    if cgroups_supported():
        pytest.skip("a writable cgroup delegation exists here")
    sandbox = Sandbox(
        namespaces=Namespace.NONE, strict=True, cgroups=CGroups(pids_max=4)
    )
    with pytest.raises(SandboxError):
        sandbox.run(lambda: None)


def test_sandbox_cgroups_unavailable_nonstrict() -> None:
    if cgroups_supported():
        pytest.skip("a writable cgroup delegation exists here")
    sandbox = Sandbox(namespaces=Namespace.NONE, cgroups=CGroups(pids_max=4))
    with pytest.warns(RuntimeWarning, match="cgroup"):
        result = sandbox.run(lambda: print("still ran"))
    assert result.ok
    assert result.stdout == b"still ran\n"


@requires_cgroups
def test_pids_max_bounds_forks() -> None:
    """pids.max=8 must make fork fail with EAGAIN, bounded attempt."""

    def fn() -> None:
        pids: list[int] = []
        try:
            for _ in range(64):
                pid = os.fork()
                if pid == 0:
                    time.sleep(30)
                    os._exit(0)
                pids.append(pid)
            print("no limit")
        except OSError as exc:
            print("limited", exc.errno)
        finally:
            for p in pids:
                with contextlib.suppress(OSError):
                    os.kill(p, signal.SIGKILL)
                    os.waitpid(p, 0)

    sandbox = Sandbox(namespaces=Namespace.NONE, cgroups=CGroups(pids_max=8))
    result = sandbox.run(fn)
    assert result.ok
    assert result.stdout == f"limited {errno.EAGAIN}\n".encode()


@requires_cgroups
def test_memory_max_oom_kills() -> None:
    """Blowing past memory.max gets the payload SIGKILLed by the oom killer."""

    def fn() -> None:
        buf = bytearray()
        while True:
            buf += b"x" * (1 << 20)

    sandbox = Sandbox(namespaces=Namespace.NONE, cgroups=CGroups(memory_max=32 << 20))
    result = sandbox.run(fn)
    assert not result.ok
    assert result.signal == signal.SIGKILL


@requires_cgroups
def test_cgroups_argv() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, cgroups=CGroups(pids_max=64))
    result = sandbox.run_argv([sys.executable, "-c", "print('limited ok')"])
    assert result.ok
    assert result.stdout == b"limited ok\n"
