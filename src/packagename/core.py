# SPDX-License-Identifier: 0BSD
"""Core package functionality."""

from __future__ import annotations


class Greeter:
    """Example class. Replace with the real API."""

    def greet(self, name: str) -> str:
        """Return a greeting for name."""
        if not name:
            raise ValueError("name must not be empty")
        return f"hello {name}"
