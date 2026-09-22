# SPDX-License-Identifier: 0BSD
"""Sandboxed code execution on Linux.

Run a Python callable or an argv command isolated by Linux namespaces,
rlimits and an optional Landlock ruleset. The default configuration is
rootless: an unprivileged user namespace gives the payload uid 0 inside
its own mount, pid, network, ipc and uts namespaces.

Requires Python 3.10+ and Linux, with unprivileged user namespaces for the
default namespace set. Landlock enforcement goes through landlockpy.

Kernel references:
https://man7.org/linux/man-pages/man7/namespaces.7.html
https://man7.org/linux/man-pages/man7/user_namespaces.7.html
https://docs.kernel.org/userspace-api/landlock.html
"""

from .errors import SandboxError, UnsupportedError
from .flags import Namespace
from .rlimits import RLimits
from .sandbox import Result, Sandbox, userns_available

__version__ = "0.1.0"

__all__ = [
    "Namespace",
    "RLimits",
    "Result",
    "Sandbox",
    "SandboxError",
    "UnsupportedError",
    "__version__",
    "userns_available",
]
