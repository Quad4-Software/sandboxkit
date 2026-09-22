# SPDX-License-Identifier: 0BSD
"""Tests for Mount specs and in-namespace filesystem isolation.

The integration tests need user+mount namespaces; the payload mounts
run inside the sandbox mount namespace, so nothing touches the host
mount table.
"""

import errno
from pathlib import Path

import pytest

from sandboxkit import Mount, Namespace, Sandbox, SandboxError

from .conftest import requires_ns

pytestmark = [pytest.mark.userns]


def test_mount_requires_target() -> None:
    with pytest.raises(ValueError, match="target"):
        Mount(target="")


def test_mount_target_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="absolute"):
        Mount(target="relative/dir", fstype="tmpfs")


def test_mount_requires_source_or_fstype() -> None:
    with pytest.raises(ValueError, match="fstype"):
        Mount(target="/x")


def test_mount_recursive_requires_bind() -> None:
    with pytest.raises(ValueError, match="recursive"):
        Mount(target="/x", fstype="tmpfs", recursive=True)


def test_bind_constructor() -> None:
    spec = Mount.bind("/a", "/b", readonly=True, recursive=True)
    assert spec.is_bind
    assert spec.readonly
    assert spec.recursive
    assert spec.source == "/a"
    assert spec.target == "/b"


def test_source_without_fstype_is_bind() -> None:
    assert Mount(target="/b", source="/a").is_bind


def test_tmpfs_constructor() -> None:
    spec = Mount.tmpfs("/scratch", size="16m", mode=0o700)
    assert spec.fstype == "tmpfs"
    assert spec.options == "size=16m,mode=700"
    assert spec.nosuid
    assert spec.nodev


def test_proc_constructor() -> None:
    spec = Mount.proc()
    assert spec.target == "/proc"
    assert spec.fstype == "proc"
    assert spec.noexec


def test_mounts_require_mount_namespace() -> None:
    with pytest.raises(ValueError, match="MOUNT"):
        Sandbox(namespaces=Namespace.USER, mounts=[Mount.proc()])


def test_root_requires_mount_namespace() -> None:
    with pytest.raises(ValueError, match="MOUNT"):
        Sandbox(namespaces=Namespace.USER, root="/rootfs")


def test_root_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="absolute"):
        Sandbox(root="rootfs")


@requires_ns(Namespace.USER | Namespace.MOUNT)
def test_bind_mount_visible(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "marker.txt").write_text("bound")

    def fn() -> None:
        print((dst / "marker.txt").read_text())

    result = Sandbox(mounts=[Mount.bind(str(src), str(dst))]).run(fn)
    assert result.ok
    assert result.stdout == b"bound\n"


@requires_ns(Namespace.USER | Namespace.MOUNT)
def test_bind_mount_readonly(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "marker.txt").write_text("bound")

    def fn() -> None:
        print((dst / "marker.txt").read_text().strip())
        try:
            (dst / "new.txt").write_text("nope")
            print("write succeeded")
        except OSError as exc:
            print("denied", exc.errno)

    result = Sandbox(mounts=[Mount.bind(str(src), str(dst), readonly=True)]).run(fn)
    assert result.ok
    assert result.stdout == f"bound\ndenied {errno.EROFS}\n".encode()
    assert not (src / "new.txt").exists()


@requires_ns(Namespace.USER | Namespace.MOUNT)
def test_tmpfs_size_enforced(tmp_path: Path) -> None:
    dst = tmp_path / "scratch"
    dst.mkdir()

    def fn() -> None:
        path = dst / "blob"
        try:
            path.write_bytes(b"x" * (8 << 20))
            print("wrote 8m")
        except OSError as exc:
            print("failed", exc.errno)

    result = Sandbox(mounts=[Mount.tmpfs(str(dst), size="4m")]).run(fn)
    assert result.ok
    assert result.stdout == f"failed {errno.ENOSPC}\n".encode()
    assert not (dst / "blob").exists()


@requires_ns(Namespace.USER | Namespace.MOUNT | Namespace.PID)
def test_proc_mount_fresh() -> None:
    def fn() -> None:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("Pid:"):
                print(line)

    result = Sandbox(mounts=[Mount.proc()]).run(fn)
    assert result.ok
    assert result.stdout == b"Pid:\t1\n"


@requires_ns(Namespace.USER | Namespace.MOUNT)
def test_mount_failure_is_fatal(tmp_path: Path) -> None:
    """A mount onto a missing target must abort the sandbox."""
    spec = Mount.bind(str(tmp_path), "/definitely/missing/target")
    with pytest.raises(SandboxError) as excinfo:
        Sandbox(mounts=[spec]).run(lambda: None)
    assert excinfo.value.errno == errno.ENOENT


@requires_ns(Namespace.USER | Namespace.MOUNT)
def test_pivot_root(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "marker.txt").write_text("new root")

    def fn() -> None:
        print(Path("/marker.txt").read_text().strip())
        print("old root visible:", Path("/etc").exists() or Path("/usr").exists())

    result = Sandbox(root=str(rootfs)).run(fn)
    assert result.ok
    assert result.stdout == b"new root\nold root visible: False\n"


@requires_ns(Namespace.USER | Namespace.MOUNT)
def test_pivot_root_with_binds(tmp_path: Path) -> None:
    """Populate the new root with binds before pivoting into it."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "bin").mkdir()
    (rootfs / "marker").mkdir()
    marker = tmp_path / "marker"
    marker.mkdir()
    (marker / "hello.txt").write_text("hi")

    def fn() -> None:
        print(Path("/bin/sh").exists() or len(list(Path("/bin").iterdir())) > 0)
        print(Path("/marker/hello.txt").read_text().strip())

    result = Sandbox(
        root=str(rootfs),
        mounts=[
            Mount.bind("/bin", str(rootfs / "bin"), readonly=True, recursive=True),
            Mount.bind(str(marker), str(rootfs / "marker")),
        ],
    ).run(fn)
    assert result.ok
    assert result.stdout == b"True\nhi\n"
