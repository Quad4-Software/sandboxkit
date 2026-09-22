# SPDX-License-Identifier: 0BSD
"""Validation tests for Sandbox and RLimits configuration."""

from collections.abc import Callable
from typing import cast

import pytest

from sandboxkit import Namespace, RLimits, Sandbox


def test_default_namespaces() -> None:
    expected = (
        Namespace.USER
        | Namespace.MOUNT
        | Namespace.PID
        | Namespace.NET
        | Namespace.IPC
        | Namespace.UTS
    )
    assert Sandbox().namespaces == expected
    assert not Sandbox().namespaces & Namespace.CGROUP


def test_namespaces_normalized() -> None:
    assert Sandbox(namespaces=Namespace(0)).namespaces is Namespace.NONE
    combined = Namespace.USER | Namespace.NET
    assert Sandbox(namespaces=combined).namespaces == combined


def test_hostname_requires_uts() -> None:
    with pytest.raises(ValueError, match="UTS"):
        Sandbox(namespaces=Namespace.USER, hostname="box")


def test_mount_proc_requires_mount() -> None:
    with pytest.raises(ValueError, match="MOUNT"):
        Sandbox(namespaces=Namespace.USER, mount_proc=True)


def test_timeout_must_be_positive() -> None:
    with pytest.raises(ValueError, match="timeout"):
        Sandbox(timeout=0)
    with pytest.raises(ValueError, match="timeout"):
        Sandbox(timeout=-1)


def test_max_output_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_output"):
        Sandbox(max_output=0)


def test_hostname_allowed_with_uts() -> None:
    sandbox = Sandbox(namespaces=Namespace.USER | Namespace.UTS, hostname="box")
    assert sandbox.hostname == "box"


def test_rlimits_rejects_negative() -> None:
    with pytest.raises(ValueError, match="memory_bytes"):
        RLimits(memory_bytes=-1)


def test_run_rejects_noncallable() -> None:
    bad = cast(Callable[[], object], "nope")
    with pytest.raises(TypeError, match="callable"):
        Sandbox(namespaces=Namespace.NONE).run(bad)


def test_run_argv_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        Sandbox(namespaces=Namespace.NONE).run_argv([])
