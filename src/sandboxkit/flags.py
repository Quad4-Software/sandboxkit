# SPDX-License-Identifier: 0BSD
"""Namespace selection flags, mirroring the CLONE_NEW* constants.

Values are the flag bits from linux/sched.h. See namespaces(7) and
unshare(2) for what each namespace isolates.
"""

from enum import IntFlag

__all__ = ["Namespace"]


class Namespace(IntFlag):
    """Linux namespaces that can be unshared for a sandbox."""

    NONE = 0
    MOUNT = 0x00020000  # CLONE_NEWNS, mount points
    CGROUP = 0x02000000  # CLONE_NEWCGROUP, cgroup root directory
    UTS = 0x04000000  # CLONE_NEWUTS, hostname and domainname
    IPC = 0x08000000  # CLONE_NEWIPC, System V IPC and POSIX message queues
    USER = 0x10000000  # CLONE_NEWUSER, uid/gid and capabilities
    PID = 0x20000000  # CLONE_NEWPID, process ids
    NET = 0x40000000  # CLONE_NEWNET, network stack
