# sandboxkit

[![CI](https://github.com/Quad4-Software/sandboxkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/sandboxkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/sandboxkit/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/sandboxkit/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/sandboxkit/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/sandboxkit)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Sandboxed code execution on Linux. Run a Python callable in a forked
child or an argv command in a subprocess, isolated by namespaces,
rlimits and Landlock. Rootless by default: an unprivileged user
namespace gives the payload uid 0 inside its own mount, pid, network
(no connectivity), ipc and uts namespaces.

Requires Python 3.10+ and Linux, with unprivileged user namespaces for the
default configuration. Landlock support comes from landlockpy and is
used when the running kernel has it.

## Install

    pip install sandboxkit

## Usage

```python
from sandboxkit import RLimits, Sandbox

sandbox = Sandbox(
    rlimits=RLimits(cpu_seconds=5, memory_bytes=64 << 20),
    timeout=10,
)
result = sandbox.run_argv(["/usr/bin/python3", "-c", "print(2 + 2)"])
assert result.ok and result.stdout == b"4\n"

# or run a callable. An OSError inside surfaces as result.errno
result = sandbox.run(lambda: print("running as uid", __import__("os").getuid()))
```

- `namespaces` picks the unshare(2) set. `Namespace.CGROUP` is opt-in.
- The real uid/gid is mapped to 0 inside, written by the parent through
  /proc/<pid>/ so it works on kernels that reject self-mapping.
- `strict=True` raises `SandboxError` on any namespace failure.
  `strict=False` (default) skips refused namespaces with a stderr note.
- `landlock=` takes a configured but unenforced `landlockpy.Ruleset`,
  restricted in the payload only, so the object stays usable.
- `hostname=` sets the UTS hostname, `mount_proc=True` mounts a fresh
  /proc, `timeout=` kills the whole sandbox tree.

## Documentation

- API: docstrings in `src/sandboxkit/`, mostly `sandbox.py`
- namespaces(7): https://man7.org/linux/man-pages/man7/namespaces.7.html
- user_namespaces(7): https://man7.org/linux/man-pages/man7/user_namespaces.7.html
- unshare(2): https://man7.org/linux/man-pages/man2/unshare.2.html
- setrlimit(2): https://man7.org/linux/man-pages/man2/setrlimit.2.html
- Landlock: https://docs.kernel.org/userspace-api/landlock.html

License: 0BSD.
