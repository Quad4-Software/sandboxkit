# SPDX-License-Identifier: 0BSD
"""Resource limits applied to the sandboxed process via setrlimit(2)."""

from __future__ import annotations

import resource
from dataclasses import dataclass, fields

__all__ = ["RLimits"]


@dataclass(frozen=True)
class RLimits:
    """Resource limits for the sandboxed process.

    Each field maps to one setrlimit(2) resource. None leaves the
    inherited limit untouched. Both the soft and the hard limit are set
    to the given value. See setrlimit(2) for units and semantics.
    """

    cpu_seconds: int | None = None  # RLIMIT_CPU
    memory_bytes: int | None = None  # RLIMIT_AS
    max_files: int | None = None  # RLIMIT_NOFILE
    max_processes: int | None = None  # RLIMIT_NPROC
    file_size: int | None = None  # RLIMIT_FSIZE
    core_size: int | None = None  # RLIMIT_CORE

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if value is not None and value < 0:
                raise ValueError(f"{field.name} must be non-negative")

    def apply(self) -> None:
        """Apply every configured limit to the calling process."""
        for attr, res in _MAP:
            value = getattr(self, attr)
            if value is not None:
                resource.setrlimit(res, (value, value))


_MAP = (
    ("cpu_seconds", resource.RLIMIT_CPU),
    ("memory_bytes", resource.RLIMIT_AS),
    ("max_files", resource.RLIMIT_NOFILE),
    ("max_processes", resource.RLIMIT_NPROC),
    ("file_size", resource.RLIMIT_FSIZE),
    ("core_size", resource.RLIMIT_CORE),
)
