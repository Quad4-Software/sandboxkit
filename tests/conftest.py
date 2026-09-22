# SPDX-License-Identifier: 0BSD

import sys

import landlockpy
import pytest

import sandboxkit
from sandboxkit import Namespace

SUPPORTED_NS = (
    sandboxkit.namespaces_supported() if sys.platform == "linux" else Namespace.NONE
)

requires_userns = pytest.mark.skipif(
    not sandboxkit.userns_available(),
    reason="unprivileged user namespaces unavailable",
)

requires_landlock = pytest.mark.skipif(
    landlockpy.abi_version() < 1, reason="kernel does not support Landlock"
)


def requires_ns(ns: Namespace) -> pytest.MarkDecorator:
    """Skip when the full sandbox path cannot create the namespace."""
    return pytest.mark.skipif(
        (SUPPORTED_NS & ns) != ns, reason=f"namespaces unavailable: {ns}"
    )
