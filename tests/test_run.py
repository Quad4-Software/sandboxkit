# SPDX-License-Identifier: 0BSD
"""Execution semantics: capture, exit status, errors, rlimits, timeout.

These tests run the payload with Namespace.NONE so they work without
kernel namespace support. The fork/pipe/wait machinery is identical.
"""

import errno
import os
import platform
import resource
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandboxkit import (
    Namespace,
    RLimits,
    Sandbox,
    SandboxError,
    UnsupportedError,
    _syscall,
    userns_available,
)

PLAIN = Sandbox(namespaces=Namespace.NONE)


def test_run_ok() -> None:
    result = PLAIN.run(lambda: None)
    assert result.ok
    assert result.returncode == 0
    assert result.errno == 0


def test_run_fn_return_value_discarded() -> None:
    assert PLAIN.run(lambda: 42).ok


def test_run_captures_stdout() -> None:
    result = PLAIN.run(lambda: print("hello sandbox"))
    assert result.ok
    assert result.stdout == b"hello sandbox\n"


def test_run_captures_stderr() -> None:
    result = PLAIN.run(lambda: print("oops", file=sys.stderr))
    assert result.stderr == b"oops\n"


def test_run_fn_oserror_errno() -> None:
    def fn() -> None:
        Path("/definitely/missing/file").read_bytes()

    result = PLAIN.run(fn)
    assert not result.ok
    assert result.errno == errno.ENOENT
    assert result.returncode == errno.ENOENT
    assert "missing" in result.message


def test_run_fn_exception() -> None:
    def fn() -> None:
        raise RuntimeError("boom")

    result = PLAIN.run(fn)
    assert not result.ok
    assert result.errno == 0
    assert result.returncode == 255
    assert "RuntimeError" in result.message
    assert "boom" in result.message


def test_run_argv_echo() -> None:
    result = PLAIN.run_argv([sys.executable, "-c", "print('hi')"])
    assert result.ok
    assert result.stdout == b"hi\n"


def test_run_argv_exitcode() -> None:
    result = PLAIN.run_argv([sys.executable, "-c", "import sys; sys.exit(7)"])
    assert not result.ok
    assert result.returncode == 7


def test_run_argv_exec_failure() -> None:
    result = PLAIN.run_argv(["/definitely/missing/binary"])
    assert not result.ok
    assert result.errno == errno.ENOENT


def test_run_argv_env() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, env={"MARKER": "yes"})
    result = sandbox.run_argv(
        [sys.executable, "-c", "import os; print(os.environ['MARKER'])"]
    )
    assert result.ok
    assert result.stdout == b"yes\n"


def test_run_argv_cwd(tmp_path: Path) -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, cwd=str(tmp_path))
    result = sandbox.run_argv([sys.executable, "-c", "import os; print(os.getcwd())"])
    assert result.ok
    assert result.stdout == f"{tmp_path}\n".encode()


def test_capture_disabled() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, capture=False)
    result = sandbox.run(lambda: print("not captured"))
    assert result.ok
    assert result.stdout == b""
    assert result.stderr == b""


def test_output_bounded() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, max_output=1024)

    def fn() -> None:
        sys.stdout.write("x" * 65536)

    result = sandbox.run(fn)
    assert result.ok
    assert len(result.stdout) == 1024


def test_timeout_kills() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, timeout=0.5)
    start = time.monotonic()
    result = sandbox.run(lambda: time.sleep(60))
    elapsed = time.monotonic() - start
    assert not result.ok
    assert result.timed_out
    assert result.signal == signal.SIGKILL
    assert elapsed < 30


def test_timeout_argv_kills() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, timeout=0.5)
    result = sandbox.run_argv([sys.executable, "-c", "import time; time.sleep(60)"])
    assert not result.ok
    assert result.timed_out


def test_memory_rlimit() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, rlimits=RLimits(memory_bytes=64 << 20))

    def fn() -> None:
        _ = b"x" * (256 << 20)

    result = sandbox.run(fn)
    assert not result.ok
    assert "MemoryError" in result.message


def test_core_size_rlimit() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, rlimits=RLimits(core_size=0))
    result = sandbox.run(lambda: print(resource.getrlimit(resource.RLIMIT_CORE)))
    assert result.ok
    assert result.stdout == b"(0, 0)\n"


def test_max_files_rlimit() -> None:
    sandbox = Sandbox(namespaces=Namespace.NONE, rlimits=RLimits(max_files=32))

    def fn() -> None:
        fds: list[int] = []
        try:
            while len(fds) < 64:
                fds.append(os.dup(0))
            print("opened all")
        except OSError as exc:
            print("failed", exc.errno)
        finally:
            for fd in fds:
                os.close(fd)

    result = sandbox.run(fn)
    assert result.ok
    assert result.stdout == f"failed {errno.EMFILE}\n".encode()


def test_leaked_grandchild_does_not_hang() -> None:
    """A payload child that outlives fn holding stdout gets killed off."""

    def fn() -> None:
        pid = os.fork()
        if pid == 0:
            time.sleep(60)
            os._exit(0)

    start = time.monotonic()
    result = PLAIN.run(fn)
    elapsed = time.monotonic() - start
    assert result.ok
    assert elapsed < 15


def test_unshare_fallback_requires_x86_64(monkeypatch: pytest.MonkeyPatch) -> None:
    """The raw syscall fallback must not call the wrong number on other archs."""
    libc = SimpleNamespace(syscall=lambda *a: 0)
    monkeypatch.setattr(_syscall, "_libc", libc)
    monkeypatch.setattr(platform, "machine", lambda: "riscv64")
    with pytest.raises(UnsupportedError):
        _syscall.unshare(0)


def test_strict_unshare_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_unshare(flags: int) -> None:
        raise OSError(errno.EPERM, "operation not permitted")

    monkeypatch.setattr(_syscall, "unshare", fake_unshare)
    sandbox = Sandbox(namespaces=Namespace.USER, strict=True)
    with pytest.raises(SandboxError) as excinfo:
        sandbox.run(lambda: None)
    assert excinfo.value.errno == errno.EPERM


def test_degraded_namespace_notes_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_unshare(flags: int) -> None:
        raise OSError(errno.EPERM, "operation not permitted")

    monkeypatch.setattr(_syscall, "unshare", fake_unshare)
    sandbox = Sandbox(namespaces=Namespace.USER | Namespace.NET)
    result = sandbox.run(lambda: None)
    assert result.ok
    assert b"skipping user namespace" in result.stderr
    assert b"skipping net namespace" in result.stderr


def test_userns_available_returns_bool() -> None:
    assert isinstance(userns_available(), bool)
