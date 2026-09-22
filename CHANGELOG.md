# Changelog

## [Unreleased]

## [0.1.0] - 2026-09-22

Initial release.

- Sandbox configuration and runner: run() executes a callable via
  os.fork, run_argv() execs a command, both returning a Result with
  exit status, errno, signal, timeout flag and bounded captured
  stdout/stderr.
- Rootless Linux namespace isolation via unshare(2): user, mount, pid,
  net, ipc and uts namespaces by default, cgroup opt-in. The parent
  writes /proc/<pid>/setgroups, uid_map and gid_map so uid 0 mapping
  works on kernels that reject self-mapping.
- Degradation policy: strict=False skips refused namespaces with a
  stderr note, strict=True raises SandboxError with the real errno.
  Setup failures that cannot degrade safely always raise.
- RLimits typed mapping over setrlimit(2): cpu_seconds, memory_bytes,
  max_files, max_processes, file_size and core_size.
- Optional Landlock enforcement through a configured landlockpy
  Ruleset, restricted in the payload process only. Warns and skips
  when the kernel lacks Landlock, raises UnsupportedError in strict
  mode.
- hostname option for the uts namespace and mount_proc for a fresh
  /proc inside the mount/pid namespaces.
- userns_available() end-to-end capability probe.
- Typed errors: SandboxError and UnsupportedError subclass OSError and
  carry real errnos.
