# SPDX-License-Identifier: 0BSD
"""Tests composing Sandbox with a landlockpy ruleset."""

import errno
import sys
from pathlib import Path

import landlockpy
import pytest
from landlockpy import AccessFS

from sandboxkit import Namespace, Sandbox, UnsupportedError

from .conftest import requires_landlock, requires_userns

pytestmark = [pytest.mark.landlock, requires_landlock]


def _ruleset(allowed: Path) -> landlockpy.Ruleset:
    allowed.mkdir(exist_ok=True)
    ruleset = landlockpy.Ruleset()
    ruleset.allow_path(allowed, AccessFS.READ_FILE | AccessFS.READ_DIR)
    ruleset.allow_path(sys.executable, AccessFS.READ_FILE | AccessFS.EXECUTE)
    return ruleset


def test_landlock_denies_path(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    (allowed / "ok.txt").write_text("ok")
    (denied / "secret.txt").write_text("secret")

    def fn() -> None:
        print(Path(allowed, "ok.txt").read_text())
        try:
            Path(denied, "secret.txt").read_text()
            print("read succeeded")
        except OSError as exc:
            print("denied", exc.errno)

    sandbox = Sandbox(namespaces=Namespace.NONE, landlock=_ruleset(allowed))
    result = sandbox.run(fn)
    assert result.ok
    assert result.stdout == f"ok\ndenied {errno.EACCES}\n".encode()


def test_landlock_survives_exec(tmp_path: Path) -> None:
    denied = tmp_path / "denied"
    denied.mkdir()
    secret = denied / "secret.txt"
    secret.write_text("secret")

    sandbox = Sandbox(
        namespaces=Namespace.NONE, landlock=_ruleset(tmp_path / "allowed")
    )
    result = sandbox.run_argv([sys.executable, "-c", f"open({str(secret)!r}).read()"])
    assert not result.ok
    assert result.returncode != 0


def test_ruleset_stays_usable(tmp_path: Path) -> None:
    ruleset = _ruleset(tmp_path)
    sandbox = Sandbox(namespaces=Namespace.NONE, landlock=ruleset)
    assert sandbox.run(lambda: None).ok
    assert sandbox.run(lambda: None).ok
    assert not ruleset.enforced
    ruleset.close()


def test_closed_ruleset_rejected() -> None:
    ruleset = landlockpy.Ruleset()
    ruleset.close()
    sandbox = Sandbox(namespaces=Namespace.NONE, landlock=ruleset)
    with pytest.raises(ValueError, match="closed"):
        sandbox.run(lambda: None)


def test_unsupported_landlock_raises_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(landlockpy, "supported", lambda: False)
    sandbox = Sandbox(
        namespaces=Namespace.NONE, strict=True, landlock=landlockpy.Ruleset()
    )
    with pytest.raises(UnsupportedError):
        sandbox.run(lambda: None)


def test_unsupported_landlock_warns_and_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(landlockpy, "supported", lambda: False)
    sandbox = Sandbox(namespaces=Namespace.NONE, landlock=landlockpy.Ruleset())
    with pytest.warns(RuntimeWarning, match="Landlock"):
        result = sandbox.run(lambda: None)
    assert result.ok


@requires_userns
def test_landlock_inside_namespaces(tmp_path: Path) -> None:
    denied = tmp_path / "denied"
    denied.mkdir()
    (denied / "secret.txt").write_text("secret")

    def fn() -> None:
        try:
            (denied / "secret.txt").read_text()
            print("read succeeded")
        except OSError as exc:
            print("denied", exc.errno)

    sandbox = Sandbox(landlock=_ruleset(tmp_path / "allowed"))
    result = sandbox.run(fn)
    assert result.ok
    assert result.stdout == f"denied {errno.EACCES}\n".encode()
