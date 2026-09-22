# SPDX-License-Identifier: 0BSD
"""Exception types raised by sandboxkit."""


class SandboxError(OSError):
    """A sandbox setup step or the sandboxed process failed."""


class UnsupportedError(SandboxError):
    """The running kernel does not support the requested feature."""
