# SPDX-License-Identifier: 0BSD

import sys

import landlockpy
import pytest

import sandboxkit

SUPPORTED_NS = (
    sandboxkit.namespaces_supported()
    if sys.platform == "linux"
    else sandboxkit.Namespace.NONE
)

requires_userns = pytest.mark.skipif(
    not sandboxkit.userns_available(),
    reason="unprivileged user namespaces unavailable",
)

requires_landlock = pytest.mark.skipif(
    landlockpy.abi_version() < 1, reason="kernel does not support Landlock"
)

requires_cgroups = pytest.mark.skipif(
    not sandboxkit.cgroups_supported(),
    reason="no writable cgroup v2 delegation",
)


def requires_ns(ns: sandboxkit.Namespace) -> pytest.MarkDecorator:
    """Skip when the full sandbox path cannot create the namespace."""
    return pytest.mark.skipif(
        (SUPPORTED_NS & ns) != ns, reason=f"namespaces unavailable: {ns}"
    )
