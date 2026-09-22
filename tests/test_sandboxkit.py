# SPDX-License-Identifier: 0BSD

import sandboxkit
from sandboxkit import (
    Namespace,
    Result,
    RLimits,
    SandboxError,
    UnsupportedError,
)


def test_version_format() -> None:
    major, minor, patch = sandboxkit.__version__.split(".")
    assert int(major) >= 0
    assert int(minor) >= 0
    assert int(patch) >= 0


def test_public_exports() -> None:
    assert sandboxkit.__all__ == [
        "Namespace",
        "RLimits",
        "Result",
        "Sandbox",
        "SandboxError",
        "UnsupportedError",
        "__version__",
        "userns_available",
    ]


def test_errors_are_oserror() -> None:
    assert issubclass(SandboxError, OSError)
    assert issubclass(UnsupportedError, SandboxError)


def test_result_defaults() -> None:
    result = Result(ok=True, returncode=0)
    assert result.errno == 0
    assert result.signal == 0
    assert not result.timed_out
    assert result.stdout == b""
    assert result.stderr == b""


def test_namespace_values() -> None:
    assert int(Namespace.MOUNT) == 0x00020000
    assert int(Namespace.USER) == 0x10000000
    assert int(Namespace.NET) == 0x40000000
    assert int(Namespace.NONE) == 0


def test_rlimits_types() -> None:
    limits = RLimits(cpu_seconds=5)
    assert limits.cpu_seconds == 5
    assert limits.memory_bytes is None
