# SPDX-License-Identifier: 0BSD

import os
import sys

import landlockpy
import pytest

import sandboxkit

SUPPORTED_NS = (
    sandboxkit.namespaces_supported()
    if sys.platform == "linux"
    else sandboxkit.Namespace.NONE
)

_STRICT = os.environ.get("Q4_REQUIRE_LIVE") == "1"

requires_userns = pytest.mark.skipif(
    not sandboxkit.userns_available() and not _STRICT,
    reason="unprivileged user namespaces unavailable",
)

requires_landlock = pytest.mark.skipif(
    landlockpy.abi_version() < 1 and not _STRICT,
    reason="kernel does not support Landlock",
)

requires_cgroups = pytest.mark.skipif(
    not sandboxkit.cgroups_supported() and not _STRICT,
    reason="no writable cgroup v2 delegation",
)


def requires_ns(ns: sandboxkit.Namespace) -> pytest.MarkDecorator:
    """Skip when the full sandbox path cannot create the namespace."""
    return pytest.mark.skipif(
        (SUPPORTED_NS & ns) != ns and not _STRICT,
        reason=f"namespaces unavailable: {ns}",
    )
