# SPDX-License-Identifier: 0BSD
"""Sandbox configuration and the fork/exec runner.

Sandbox describes the isolation for one payload: Linux namespaces via
unshare(2), resource limits via setrlimit(2) and an optional Landlock
ruleset from landlockpy. run() executes a Python callable in a forked
child. run_argv() execs an argv command. Both return a Result with the
exit status and bounded captured output.

The user-namespace uid/gid map is written by the parent through
/proc/<pid>/, the only unprivileged mapping path current kernels accept.
A process inside the new namespace cannot write its own map. See
user_namespaces(7). The payload process exits via os._exit so parent
atexit handlers and buffered state never run inside the sandbox.

References:
https://man7.org/linux/man-pages/man7/namespaces.7.html
https://man7.org/linux/man-pages/man7/user_namespaces.7.html
https://man7.org/linux/man-pages/man2/unshare.2.html
https://man7.org/linux/man-pages/man2/setrlimit.2.html
https://docs.kernel.org/userspace-api/landlock.html
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import selectors
import signal
import sys
import time
import warnings
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

import landlockpy

from . import _proto, _syscall
from .errors import SandboxError, UnsupportedError
from .flags import Namespace
from .rlimits import RLimits

__all__ = ["Result", "Sandbox", "namespaces_supported", "userns_available"]

_KILL_GRACE = 5.0
"""Seconds to drain child pipes after a timeout kill."""

_SETUP_CAP = 30.0
"""Seconds the child may spend in namespace setup before it is killed."""

_RES_CAP = 4096
"""Upper bound on the result record, far above its real size."""

_UNSHARE_ORDER = (
    Namespace.MOUNT,
    Namespace.CGROUP,
    Namespace.IPC,
    Namespace.UTS,
    Namespace.PID,
    Namespace.NET,
)


@dataclass(frozen=True)
class Result:
    """Outcome of a sandboxed run.

    ok is True when the payload finished without error: the callable
    returned, or the exec'd command exited 0. returncode is the exit
    status of the outer sandbox child, negative when it died to a
    signal. errno carries the payload's OSError errno (EACCES, ENOMEM,
    ...) when one was reported over the result pipe. signal is the
    killing signal. timed_out marks a wall-clock kill. stdout and stderr
    hold the captured output truncated to max_output. message carries
    detail for exceptions and setup failures.
    """

    ok: bool
    returncode: int
    errno: int = 0
    signal: int = 0
    timed_out: bool = False
    stdout: bytes = b""
    stderr: bytes = b""
    message: str = ""


@dataclass
class Sandbox:
    """Isolation settings and runner for a sandboxed payload.

    namespaces defaults to user, mount, pid, net, ipc and uts: rootless
    isolation with no network. cgroup is opt-in because it usually needs
    real privileges. With strict=False (default) a namespace the kernel
    refuses is skipped with a note on the child's stderr. strict=True
    turns that failure into SandboxError raised to the caller. Setup
    failures that cannot degrade safely, such as a failed uid_map write,
    rlimit, Landlock enforcement or mount, always raise SandboxError.

    hostname requires Namespace.UTS. mount_proc mounts a fresh /proc
    inside the mount namespace and is most useful with Namespace.PID.
    landlock takes a configured but unenforced landlockpy.Ruleset. It is
    restricted in the payload process only, so the object stays usable.
    timeout kills the whole sandbox tree after that many seconds of
    payload time. env replaces os.environ in the payload and cwd becomes
    its working directory.
    """

    namespaces: Namespace = (
        Namespace.USER
        | Namespace.MOUNT
        | Namespace.PID
        | Namespace.NET
        | Namespace.IPC
        | Namespace.UTS
    )
    strict: bool = False
    hostname: str | None = None
    mount_proc: bool = False
    rlimits: RLimits | None = None
    landlock: landlockpy.Ruleset | None = None
    timeout: float | None = None
    capture: bool = True
    max_output: int = 1 << 20
    env: Mapping[str, str] | None = None
    cwd: str | None = None

    def __post_init__(self) -> None:
        self.namespaces = Namespace(self.namespaces)
        if self.hostname is not None and not self.namespaces & Namespace.UTS:
            raise ValueError("hostname requires Namespace.UTS")
        if self.mount_proc and not self.namespaces & Namespace.MOUNT:
            raise ValueError("mount_proc requires Namespace.MOUNT")
        if self.timeout is not None and self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_output <= 0:
            raise ValueError("max_output must be positive")

    def run(self, fn: Callable[[], object]) -> Result:
        """Run fn in a forked, sandboxed child and return its Result.

        The return value of fn is discarded. Report through captured
        stdout/stderr or by raising. An OSError inside fn surfaces as
        Result.errno, any other exception as Result.message. The child
        is a fork of the caller, so the usual fork(2) caveats apply:
        run() from a single-threaded context where possible.
        """
        if not callable(fn):
            raise TypeError("fn must be callable")
        return self._spawn(fn, None)

    def run_argv(self, argv: Sequence[str]) -> Result:
        """Exec argv[0] inside the sandbox and return its Result.

        argv[0] is resolved against the payload's PATH, see execvp(3).
        """
        if not argv:
            raise ValueError("argv must not be empty")
        return self._spawn(None, [str(arg) for arg in argv])

    def _effective_ruleset(self) -> landlockpy.Ruleset | None:
        ruleset = self.landlock
        if ruleset is None:
            return None
        if ruleset.closed:
            raise ValueError("ruleset is closed")
        if ruleset.enforced:
            raise ValueError("ruleset is already enforced")
        if not landlockpy.supported():
            if self.strict:
                raise UnsupportedError(
                    errno.EOPNOTSUPP, "kernel does not support Landlock"
                )
            warnings.warn(
                "Landlock is not supported by the running kernel, skipping ruleset",
                RuntimeWarning,
                stacklevel=3,
            )
            return None
        return ruleset

    def _spawn(self, fn: Callable[[], object] | None, argv: list[str] | None) -> Result:
        if sys.platform != "linux":
            raise UnsupportedError("sandboxkit is only available on Linux")
        ruleset = self._effective_ruleset()
        _flush()  # keep the parent's buffered output out of the child's capture
        ctl_r, ctl_w = os.pipe()
        ack_r, ack_w = os.pipe()
        res_r, res_w = os.pipe()
        out_r, out_w = os.pipe() if self.capture else (-1, -1)
        err_r, err_w = os.pipe() if self.capture else (-1, -1)
        try:
            pid = os.fork()
        except OSError:
            for fd in (
                ctl_r,
                ctl_w,
                ack_r,
                ack_w,
                res_r,
                res_w,
                out_r,
                out_w,
                err_r,
                err_w,
            ):
                with contextlib.suppress(OSError):
                    os.close(fd)
            raise
        if pid == 0:
            _child(
                self,
                fn,
                argv,
                ruleset,
                ctl_w,
                ack_r,
                res_w,
                out_w,
                err_w,
                (ctl_r, ack_w, res_r, out_r, err_r),
            )
        for fd in (ctl_w, ack_r, res_w, out_w, err_w):
            if fd >= 0:
                os.close(fd)
        with contextlib.suppress(OSError):
            os.setpgid(pid, pid)
        return self._parent(pid, ctl_r, ack_w, res_r, out_r, err_r)

    def _parent(
        self, pid: int, ctl_r: int, ack_w: int, res_r: int, out_r: int, err_r: int
    ) -> Result:
        live = {fd for fd in (ctl_r, ack_w, res_r, out_r, err_r) if fd >= 0}

        def close(fd: int) -> None:
            if fd in live:
                live.discard(fd)
                with contextlib.suppress(OSError):
                    os.close(fd)

        try:
            payload_pid, setup_timeout = _ctl_exchange(pid, ctl_r, ack_w)
            close(ctl_r)
            close(ack_w)
            sel = selectors.DefaultSelector()
            bufs = {"res": bytearray(), "out": bytearray(), "err": bytearray()}
            for fd, role in ((res_r, "res"), (out_r, "out"), (err_r, "err")):
                if fd >= 0:
                    os.set_blocking(fd, False)
                    sel.register(fd, selectors.EVENT_READ, role)
            now = time.monotonic()
            if setup_timeout:
                deadline = now  # already expired, the drain loop kills
            elif self.timeout is not None:
                deadline = now + self.timeout
            else:
                deadline = None
            try:
                status, timed_out = self._drain(
                    sel, bufs, pid, payload_pid, deadline, close
                )
            finally:
                sel.close()
            if status is None:
                _, status = os.waitpid(pid, 0)
            return _result(
                status,
                bytes(bufs["res"]),
                bytes(bufs["out"]),
                bytes(bufs["err"]),
                timed_out,
            )
        finally:
            for fd in live:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def _drain(
        self,
        sel: selectors.BaseSelector,
        bufs: dict[str, bytearray],
        pid: int,
        payload_pid: int,
        deadline: float | None,
        close: Callable[[int], None],
    ) -> tuple[int | None, bool]:
        """Drain child pipes until exit and EOF, killing past deadline."""
        status: int | None = None
        timed_out = False
        hard_deadline: float | None = None
        while True:
            # A grandchild holding an output pipe must not hang the run:
            # bound the post-exit drain once the child is reaped.
            if status is None:
                status = _try_reap(pid)
                if status is not None and hard_deadline is None:
                    hard_deadline = time.monotonic() + _KILL_GRACE
            if status is not None and not sel.get_map():
                break
            if hard_deadline is not None and time.monotonic() >= hard_deadline:
                _kill_tree(pid, payload_pid)
                break
            now = time.monotonic()
            if not timed_out and deadline is not None and now >= deadline:
                timed_out = True
                _kill_tree(pid, payload_pid)
                hard_deadline = now + _KILL_GRACE
            wait = 0.05
            for limit in (deadline, hard_deadline):
                if limit is not None:
                    wait = min(wait, max(limit - now, 0.001))
            for key, _ in sel.select(wait):
                self._drain_event(sel, key, bufs, close)
        return status, timed_out

    def _drain_event(
        self,
        sel: selectors.BaseSelector,
        key: selectors.SelectorKey,
        bufs: dict[str, bytearray],
        close: Callable[[int], None],
    ) -> None:
        try:
            chunk = os.read(key.fd, 65536)
        except BlockingIOError:
            return
        if not chunk:
            sel.unregister(key.fd)
            close(key.fd)
            return
        buf = bufs[key.data]
        cap = _RES_CAP if key.data == "res" else self.max_output
        room = cap - len(buf)
        if room > 0:
            buf += chunk[:room]


def _ctl_exchange(pid: int, ctl_r: int, ack_w: int) -> tuple[int, bool]:
    """Run the setup handshake, returning (payload_pid, timed_out)."""
    limit = time.monotonic() + _SETUP_CAP
    data, timed_out = _read_exact(ctl_r, _proto.CTL.size, limit)
    if timed_out or len(data) < _proto.CTL.size:
        return 0, timed_out
    code, _ = _proto.CTL.unpack(data)
    ack = 0
    if code == _proto.CTL_USERNS_OK:
        try:
            _write_id_maps(pid, os.getuid(), os.getgid())
        except OSError as exc:
            ack = exc.errno or errno.EIO
    with contextlib.suppress(OSError):
        os.write(ack_w, _proto.ACK.pack(ack))
    data, timed_out = _read_exact(ctl_r, _proto.PIDMSG.size, limit)
    if timed_out or len(data) < _proto.PIDMSG.size:
        return 0, timed_out
    (payload_pid,) = _proto.PIDMSG.unpack(data)
    return payload_pid, False


def _result(
    status: int,
    res_data: bytes,
    stdout: bytes,
    stderr: bytes,
    timed_out: bool,
) -> Result:
    """Build the Result, raising SandboxError on fatal setup records."""
    record = _proto.decode_record(res_data) if res_data else None
    if record is not None and record.kind == _proto.REC_SETUP:
        exc_type = (
            UnsupportedError
            if record.errno in (errno.ENOSYS, errno.EOPNOTSUPP)
            else SandboxError
        )
        raise exc_type(record.errno or errno.EIO, record.message)
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        return Result(
            ok=False,
            returncode=-sig,
            signal=sig,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
        )
    code = os.WEXITSTATUS(status)
    if record is None:
        return Result(
            ok=code == 0,
            returncode=code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
        )
    ok = record.kind == _proto.REC_OK
    return Result(
        ok=ok,
        returncode=code,
        errno=0 if ok else record.errno,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
        message=record.message,
    )


def _read_exact(fd: int, size: int, limit: float) -> tuple[bytes, bool]:
    """Read up to size bytes before limit and return (data, timed_out)."""
    buf = bytearray()
    sel = selectors.DefaultSelector()
    sel.register(fd, selectors.EVENT_READ)
    try:
        while len(buf) < size:
            remaining = limit - time.monotonic()
            if remaining <= 0:
                return bytes(buf), True
            for key, _ in sel.select(min(0.05, remaining)):
                chunk = os.read(key.fd, size - len(buf))
                if not chunk:
                    return bytes(buf), False
                buf += chunk
        return bytes(buf), False
    finally:
        sel.close()


def _try_reap(pid: int) -> int | None:
    """Return the child's wait status if it has exited, else None."""
    done, status = os.waitpid(pid, os.WNOHANG)
    return status if done == pid else None


def _kill_tree(outer_pid: int, payload_pid: int) -> None:
    """SIGKILL the payload, its process group and the outer child."""
    for target in (payload_pid, outer_pid):
        if target > 0:
            with contextlib.suppress(OSError):
                os.kill(target, signal.SIGKILL)
    with contextlib.suppress(OSError):
        os.killpg(outer_pid, signal.SIGKILL)


def _write_id_maps(
    pid: int, uid: int, gid: int, proc_root: str | Path = "/proc"
) -> None:
    """Map the child's real uid/gid to 0 inside its user namespace.

    Must run in the parent user namespace. A process inside the new
    namespace cannot write its own map. See user_namespaces(7).
    """
    base = Path(proc_root) / str(pid)
    (base / "setgroups").write_text("deny")
    (base / "uid_map").write_text(f"0 {uid} 1")
    (base / "gid_map").write_text(f"0 {gid} 1")


def userns_available() -> bool:
    """Probe whether unprivileged user namespaces work end to end.

    Forks a child that unshares CLONE_NEWUSER and checks the parent can
    map its uid to 0, the same path Sandbox uses. False means configs
    with Namespace.USER fail or degrade on this kernel.
    """
    ctl_r, ctl_w = os.pipe()
    ack_r, ack_w = os.pipe()
    try:
        pid = os.fork()
    except OSError:
        for fd in (ctl_r, ctl_w, ack_r, ack_w):
            with contextlib.suppress(OSError):
                os.close(fd)
        raise
    if pid == 0:
        try:
            os.close(ctl_r)
            os.close(ack_w)
            _syscall.unshare(int(Namespace.USER))
            os.write(ctl_w, b"1")
            os.read(ack_r, 1)
            os._exit(0 if os.getuid() == 0 else 1)
        except BaseException:  # noqa: BLE001 - must not propagate in the child
            os._exit(1)
    os.close(ctl_w)
    os.close(ack_r)
    ok = os.read(ctl_r, 1) == b"1"
    if ok:
        try:
            _write_id_maps(pid, os.getuid(), os.getgid())
        except OSError:
            ok = False
    with contextlib.suppress(OSError):
        os.write(ack_w, b"0")
    os.close(ctl_r)
    os.close(ack_w)
    _, status = os.waitpid(pid, 0)
    return ok and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def namespaces_supported() -> Namespace:
    """Probe which namespaces this kernel lets the caller unshare.

    Uses the same path Sandbox takes: a child unshares CLONE_NEWUSER,
    the parent writes the id maps, then the child tries every other
    CLONE_NEW* flag. Returns the set that applied; Namespace.NONE means
    even the user namespace failed. Kernels may allow USER but refuse
    the rest, for example under Ubuntu's AppArmor restrictions.
    """
    ctl_r, ctl_w = os.pipe()
    ack_r, ack_w = os.pipe()
    res_r, res_w = os.pipe()
    try:
        pid = os.fork()
    except OSError:
        for fd in (ctl_r, ctl_w, ack_r, ack_w, res_r, res_w):
            with contextlib.suppress(OSError):
                os.close(fd)
        raise
    if pid == 0:
        applied = 0
        try:
            os.close(ctl_r)
            os.close(ack_w)
            os.close(res_r)
            _syscall.unshare(int(Namespace.USER))
            os.write(ctl_w, b"1")
            if os.read(ack_r, 1) == b"0":
                applied = int(Namespace.USER)
                for ns in _UNSHARE_ORDER:
                    with contextlib.suppress(OSError):
                        _syscall.unshare(int(ns))
                        applied |= int(ns)
            os.write(res_w, _proto.PIDMSG.pack(applied))
        except BaseException:  # noqa: BLE001 - must not propagate in the child
            os._exit(1)
        os._exit(0)
    os.close(ctl_w)
    os.close(ack_r)
    os.close(res_w)
    ok = os.read(ctl_r, 1) == b"1"
    ack = b"0"
    if ok:
        try:
            _write_id_maps(pid, os.getuid(), os.getgid())
        except OSError:
            ack = b"1"
    with contextlib.suppress(OSError):
        os.write(ack_w, ack)
    data = _read_exact(res_r, _proto.PIDMSG.size, time.monotonic() + _SETUP_CAP)[0]
    applied = _proto.PIDMSG.unpack(data)[0] if len(data) == _proto.PIDMSG.size else 0
    os.close(ctl_r)
    os.close(ack_w)
    os.close(res_r)
    os.waitpid(pid, 0)
    return Namespace(applied)


def _keep_fd(fd: int) -> int:
    """Move fd above 2 so dup2 cannot clobber it. Returns the fd to use."""
    if fd < 0 or fd > 2:
        return fd
    new_fd = int(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3))
    os.close(fd)
    return new_fd


def _note(message: str) -> None:
    with contextlib.suppress(OSError):
        os.write(2, f"sandboxkit: {message}\n".encode())


def _flush() -> None:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.flush()


def _send_record(fd: int, kind: int, err: int, message: str) -> None:
    with contextlib.suppress(OSError):
        os.write(fd, _proto.encode_record(kind, err, message.encode(errors="replace")))


def _child(
    cfg: Sandbox,
    fn: Callable[[], object] | None,
    argv: list[str] | None,
    ruleset: landlockpy.Ruleset | None,
    ctl_w: int,
    ack_r: int,
    res_w: int,
    out_w: int,
    err_w: int,
    close_fds: tuple[int, ...],
) -> NoReturn:
    try:
        ctl_w = _keep_fd(ctl_w)
        ack_r = _keep_fd(ack_r)
        res_w = _keep_fd(res_w)
        out_w = _keep_fd(out_w)
        err_w = _keep_fd(err_w)
        for fd in close_fds:
            with contextlib.suppress(OSError):
                os.close(fd)
        if out_w >= 0:
            os.dup2(out_w, 1)
            os.close(out_w)
            sys.stdout = os.fdopen(1, "w", buffering=1)
        if err_w >= 0:
            os.dup2(err_w, 2)
            os.close(err_w)
            sys.stderr = os.fdopen(2, "w", buffering=1, errors="backslashreplace")
        applied = _unshare_stage(cfg, ctl_w, ack_r, res_w)
        if cfg.hostname is not None:
            if applied & Namespace.UTS:
                _syscall.sethostname(cfg.hostname)
            else:
                _note("hostname skipped: uts namespace unavailable")
        if applied & Namespace.PID:
            payload_pid = os.fork()
            if payload_pid == 0:
                os.close(ctl_w)
                os.close(ack_r)
                _payload(cfg, fn, argv, ruleset, res_w, applied)
            os.write(ctl_w, _proto.PIDMSG.pack(payload_pid))
            os.close(res_w)
            _forward(payload_pid)
        os.write(ctl_w, _proto.PIDMSG.pack(os.getpid()))
        _payload(cfg, fn, argv, ruleset, res_w, applied)
    except OSError as exc:
        _send_record(res_w, _proto.REC_SETUP, exc.errno or errno.EIO, str(exc))
        os._exit(1)
    except BaseException:  # noqa: BLE001 - must not propagate in the child
        os._exit(1)


def _userns_stage(cfg: Sandbox, ctl_w: int, ack_r: int, res_w: int) -> int:
    """Unshare CLONE_NEWUSER and let the parent write the id maps.

    Returns Namespace.USER when the namespace was created, else 0.
    """
    userns_err = 0
    if cfg.namespaces & Namespace.USER:
        try:
            _syscall.unshare(int(Namespace.USER))
        except OSError as exc:
            userns_err = exc.errno or errno.EIO
            os.write(ctl_w, _proto.CTL.pack(_proto.CTL_USERNS_ERR, userns_err))
        else:
            os.write(ctl_w, _proto.CTL.pack(_proto.CTL_USERNS_OK, 0))
    else:
        os.write(ctl_w, _proto.CTL.pack(_proto.CTL_USERNS_NONE, 0))
    ack = os.read(ack_r, 1)
    if not ack or ack[0] != 0:
        _send_record(
            res_w,
            _proto.REC_SETUP,
            ack[0] if ack else errno.EIO,
            "parent could not write uid_map/gid_map",
        )
        os._exit(1)
    if not cfg.namespaces & Namespace.USER:
        return 0
    if userns_err:
        if cfg.strict:
            raise SandboxError(userns_err, f"CLONE_NEWUSER: {os.strerror(userns_err)}")
        _note(f"skipping user namespace: {os.strerror(userns_err)}")
        return 0
    return int(Namespace.USER)


def _unshare_stage(cfg: Sandbox, ctl_w: int, ack_r: int, res_w: int) -> int:
    """Create the user namespace, handshake with the parent, then the rest."""
    applied = _userns_stage(cfg, ctl_w, ack_r, res_w)
    for ns in _UNSHARE_ORDER:
        if not cfg.namespaces & ns:
            continue
        try:
            _syscall.unshare(int(ns))
        except OSError as exc:
            err = exc.errno or errno.EIO
            ns_name = ns.name or str(int(ns))
            if cfg.strict:
                raise SandboxError(
                    err, f"{ns_name} namespace: {os.strerror(err)}"
                ) from exc
            _note(f"skipping {ns_name.lower()} namespace: {os.strerror(err)}")
        else:
            applied |= ns
    return applied


def _forward(payload_pid: int) -> NoReturn:
    """Wait for the payload child and propagate its exit status."""
    _, status = os.waitpid(payload_pid, 0)
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
    os._exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)


def _payload_setup(
    cfg: Sandbox, ruleset: landlockpy.Ruleset | None, applied: int
) -> None:
    """Apply mount/env/cwd/rlimits/Landlock inside the payload process."""
    if cfg.mount_proc:
        if applied & Namespace.MOUNT:
            _syscall.mount("proc", "/proc", "proc")
        else:
            _note("mount_proc skipped: mount namespace unavailable")
    if cfg.env is not None:
        os.environ.clear()
        os.environ.update(cfg.env)
    if cfg.cwd is not None:
        os.chdir(cfg.cwd)
    if cfg.rlimits is not None:
        cfg.rlimits.apply()
    if ruleset is not None:
        ruleset.restrict()


def _payload(
    cfg: Sandbox,
    fn: Callable[[], object] | None,
    argv: list[str] | None,
    ruleset: landlockpy.Ruleset | None,
    res_w: int,
    applied: int,
) -> NoReturn:
    try:
        _payload_setup(cfg, ruleset, applied)
    except OSError as exc:
        _send_record(res_w, _proto.REC_SETUP, exc.errno or errno.EIO, str(exc))
        _flush()
        os._exit(1)
    if argv is not None:
        try:
            os.execvpe(argv[0], argv, dict(os.environ))  # noqa: S606  # nosec B606
        except OSError as exc:
            err = exc.errno or errno.EIO
            _send_record(res_w, _proto.REC_EXEC, err, str(exc))
            _flush()
            os._exit(err if err < 256 else 127)
    try:
        if fn is not None:
            fn()
    except OSError as exc:
        err = exc.errno or errno.EIO
        _send_record(res_w, _proto.REC_OSERROR, err, str(exc))
        _flush()
        os._exit(err if err < 256 else 1)
    except BaseException as exc:  # noqa: BLE001 - reported over the pipe
        _send_record(res_w, _proto.REC_EXCEPTION, 0, f"{type(exc).__name__}: {exc}")
        _flush()
        os._exit(255)
    _send_record(res_w, _proto.REC_OK, 0, "")
    _flush()
    os._exit(0)
