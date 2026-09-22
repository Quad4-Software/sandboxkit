# Changelog

## [0.2.0] - Unreleased

- CGroups typed mapping over the cgroup v2 interface files:
  memory_max (memory.max), memory_high (memory.high), pids_max
  (pids.max), cpu_max (cpu.max quota/period), cpu_weight and
  io_weight. The parent creates a leaf cgroup inside the caller's
  delegated subtree, enables the needed controllers through
  cgroup.subtree_control and moves the sandbox process in before the
  payload runs. cgroup v1 and missing delegations raise
  UnsupportedError/SandboxError in strict mode and degrade with a
  warning otherwise. cgroups_supported() probes the same path.
- Mount specs for the payload's mount namespace: Mount.bind(),
  Mount.tmpfs(), Mount.proc() and Mount.sysfs(), plus the generic
  Mount dataclass with readonly/nosuid/nodev/noexec flags and an
  options string. Readonly binds use the documented bind+remount
  two-step. Mounts run after the namespace is made MS_PRIVATE so they
  cannot propagate to the host, before env/cwd, rlimits and Landlock;
  any mount failure aborts the sandbox.
- root= pivots the payload into a caller-prepared directory via
  pivot_root(2), detaching the old root with umount2(MNT_DETACH).
- mounts= and root= require Namespace.MOUNT, matching the existing
  mount_proc validation.

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
