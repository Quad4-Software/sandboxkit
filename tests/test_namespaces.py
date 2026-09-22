# SPDX-License-Identifier: 0BSD
"""Integration tests that create real namespaces via unshare(2)."""

import os
import socket
import sys
from pathlib import Path

import pytest

from sandboxkit import Sandbox

from .conftest import requires_userns

pytestmark = [pytest.mark.userns, requires_userns]


def test_uid_zero_inside() -> None:
    result = Sandbox().run(lambda: print(os.getuid(), os.getgid()))
    assert result.ok
    assert result.stdout == b"0 0\n"


def test_real_uid_preserved_outside() -> None:
    assert os.getuid() != 0


def test_pid_namespace() -> None:
    result = Sandbox().run(lambda: print(os.getpid()))
    assert result.ok
    assert result.stdout == b"1\n"


def test_uts_hostname() -> None:
    result = Sandbox(hostname="sandboxed").run(lambda: print(socket.gethostname()))
    assert result.ok
    assert result.stdout == b"sandboxed\n"


def test_net_namespace_isolated() -> None:
    result = Sandbox().run(lambda: print(len(socket.if_nameindex())))
    assert result.ok
    assert result.stdout == b"1\n"  # only lo, and it is down


def test_net_namespace_no_route() -> None:
    def fn() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect(("127.0.0.1", 9))
            print("connected")
        except OSError as exc:
            print("failed", exc.errno)
        finally:
            sock.close()

    result = Sandbox().run(fn)
    assert result.ok
    assert result.stdout.startswith(b"failed ")


def test_mount_proc() -> None:
    def fn() -> None:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("Pid:"):
                print(line)

    result = Sandbox(mount_proc=True).run(fn)
    assert result.ok
    assert result.stdout == b"Pid:\t1\n"


def test_run_argv_sandboxed() -> None:
    result = Sandbox().run_argv(
        [sys.executable, "-c", "import os; print(os.getuid(), os.getpid())"]
    )
    assert result.ok
    assert result.stdout == b"0 1\n"


def test_strict_mode_full_stack() -> None:
    result = Sandbox(strict=True).run(lambda: print("strict ok"))
    assert result.ok
    assert result.stdout == b"strict ok\n"


def test_ipc_namespace() -> None:
    def fn() -> None:
        shm = Path("/proc/sysvipc/shm")
        print(shm.exists() and len(shm.read_text().splitlines()) <= 1)

    result = Sandbox(mount_proc=True).run(fn)
    assert result.ok
    assert result.stdout == b"True\n"


def test_timeout_kills_whole_tree() -> None:
    sandbox = Sandbox(timeout=0.5)
    result = sandbox.run_argv([sys.executable, "-c", "import time; time.sleep(60)"])
    assert not result.ok
    assert result.timed_out
