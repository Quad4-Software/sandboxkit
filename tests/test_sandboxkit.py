# SPDX-License-Identifier: 0BSD

import sandboxkit


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
        "namespaces_supported",
        "userns_available",
    ]


def test_errors_are_oserror() -> None:
    assert issubclass(sandboxkit.SandboxError, OSError)
    assert issubclass(sandboxkit.UnsupportedError, sandboxkit.SandboxError)


def test_result_defaults() -> None:
    result = sandboxkit.Result(ok=True, returncode=0)
    assert result.errno == 0
    assert result.signal == 0
    assert not result.timed_out
    assert result.stdout == b""
    assert result.stderr == b""


def test_namespace_values() -> None:
    assert int(sandboxkit.Namespace.MOUNT) == 0x00020000
    assert int(sandboxkit.Namespace.USER) == 0x10000000
    assert int(sandboxkit.Namespace.NET) == 0x40000000
    assert int(sandboxkit.Namespace.NONE) == 0


def test_rlimits_types() -> None:
    limits = sandboxkit.RLimits(cpu_seconds=5)
    assert limits.cpu_seconds == 5
    assert limits.memory_bytes is None
