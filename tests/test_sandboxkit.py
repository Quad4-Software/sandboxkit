# SPDX-License-Identifier: 0BSD

import pytest

import sandboxkit
from sandboxkit import Greeter


def test_version_format() -> None:
    major, minor, patch = sandboxkit.__version__.split(".")
    assert int(major) >= 0
    assert int(minor) >= 0
    assert int(patch) >= 0


def test_greet() -> None:
    assert Greeter().greet("quad4") == "hello quad4"


def test_greet_rejects_empty_name() -> None:
    with pytest.raises(ValueError, match="empty"):
        Greeter().greet("")
