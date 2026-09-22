# SPDX-License-Identifier: 0BSD
"""Tests for the parent-side uid_map/gid_map writer."""

from pathlib import Path

import pytest

from sandboxkit.sandbox import _write_id_maps


def test_write_id_maps(tmp_path: Path) -> None:
    base = tmp_path / "1234"
    base.mkdir()
    _write_id_maps(1234, 1000, 100, proc_root=tmp_path)
    assert (base / "setgroups").read_text() == "deny"
    assert (base / "uid_map").read_text() == "0 1000 1"
    assert (base / "gid_map").read_text() == "0 100 1"


def test_write_id_maps_missing_dir(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _write_id_maps(9999, 1000, 100, proc_root=tmp_path)
