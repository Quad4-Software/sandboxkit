# SPDX-License-Identifier: 0BSD
"""Sandboxed code execution on Linux.

Run a Python callable or an argv command isolated by Linux namespaces,
rlimits, cgroup v2 limits, payload mounts and an optional Landlock
ruleset. The default configuration is rootless: an unprivileged user
namespace gives the payload uid 0 inside its own mount, pid, network,
ipc and uts namespaces.

Requires Python 3.10+ and Linux, with unprivileged user namespaces for the
default namespace set. Landlock enforcement goes through landlockpy.

Kernel references:
https://man7.org/linux/man-pages/man7/namespaces.7.html
https://man7.org/linux/man-pages/man7/user_namespaces.7.html
https://docs.kernel.org/userspace-api/landlock.html
"""

from .cgroups import CGroups, cgroups_supported
from .errors import SandboxError, UnsupportedError
from .flags import Namespace
from .mounts import Mount
from .rlimits import RLimits
from .sandbox import Result, Sandbox, namespaces_supported, userns_available

__version__ = "0.2.0"

__all__ = [
    "CGroups",
    "Mount",
    "Namespace",
    "RLimits",
    "Result",
    "Sandbox",
    "SandboxError",
    "UnsupportedError",
    "__version__",
    "cgroups_supported",
    "namespaces_supported",
    "userns_available",
]
