# SPDX-License-Identifier: 0BSD

import landlockpy
import pytest

import sandboxkit

requires_userns = pytest.mark.skipif(
    not sandboxkit.userns_available(),
    reason="unprivileged user namespaces unavailable",
)

requires_landlock = pytest.mark.skipif(
    landlockpy.abi_version() < 1, reason="kernel does not support Landlock"
)
