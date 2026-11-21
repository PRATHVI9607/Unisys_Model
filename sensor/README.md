# kubeheal-sensor (default event source)

eBPF file-activity sensor for the security agent. It runs as container `sensor` in the security-agent DaemonSet
(`deploy/k8s/base/security-agent-daemonset.yaml`) and appends Falco-shaped JSON lines to
`/var/run/kubeheal/events.jsonl` (emptyDir shared with the agent, `FALCO_EVENTS_PATH`). The agent's `parse_line`,
`FalcoTail` (hole punching) and features are unchanged. Falco stays available: `EVENT_SOURCE=falco ./deploy/scripts/install.sh`
(`deploy/k8s/components/falco-source`).

Why: Falco's single event thread caps at ~1900 alerts/s per node. With 10 busy pods its lag grew ~0.8 s per second
and a ransomware pod was killed minutes late (missed entirely in the 20-pod evaluation). The sensor filters in the kernel.

## Design

- **Hooks.** One program per VFS security hook, attached after the lookup and permission checks, so failed
  lookups never appear: `file_open` (opens; flags from `f_flags`, still holding `O_CREAT`/`O_TRUNC`), `path_rename`,
  `path_unlink`, `path_truncate` (truncate), `file_truncate` (ftruncate; skipped when called from an `O_TRUNC` open),
  `path_chmod` (chmod/fchmod/fchmodat). Each exists twice: `lsm/` (never denies, passes the previous verdict on) and
  `fexit/security_*`. At start the sensor performs each operation itself and keeps, per hook, the `lsm/` program if it
  saw it, else the `fexit/` one, and logs the choice (`hooks open=lsm ...`). `lsm/` needs `bpf` among the active LSMs;
  `fexit/` misses calls the kernel inlined (LTO kernels: `security_file_open` is inlined into `do_dentry_open` on
  CachyOS 7.3, so fexit sees no opens there). A hook neither variant sees is logged as a WARNING.
- **Paths.** Resolved in BPF like `d_path()`: dentry `d_parent` up to the mount root, across mounts up to the task's
  `fs->root` (bounded `bpf_loop`, 64 steps), so the path is the one inside the container (`/data/x`) whatever the
  argument was: relative, dirfd-relative, `/./data`, `..`, or an fd (ftruncate, fchmod). Paths not reachable from the
  task root (overlayfs backing files, internal mounts) and paths over 254 bytes are dropped, never cut.
- **Kernel filter, in order:** task under the `kubepods` cgroup (`bpf_current_task_under_cgroup`: a new pod is covered
  from its first syscall); container cgroup not in `skip` (namespaces from `--exclude-ns`, default `kubeheal`, added
  once resolved; userspace also drops them); resolved path matches a `--prefix` (rodata, default `/data/`). Only then a
  ring-buffer record is reserved (288 B, 544 B for renames; 16 MiB ring). Reserve failures and walk-pool exhaustion
  are per-CPU counters (`drops`, `pool_full` in the stats line), fexit recursion misses come from `bpf_prog_info`.
- **Identity.** cgroup id -> pod uid + container id from the cgroup v2 tree (`kubepods*/...pod<uid>.../cri-containerd-<id>.scope`);
  uid -> namespace/name from the kubelet's pod log directories `/var/log/pods/<ns>_<pod>_<uid>`, which the kubelet
  creates before the sandbox starts, for every pod (automount off and hostNetwork included). No API access, RBAC or
  TLS crate. An unknown cgroup triggers a rescan (at most every 100 ms); its records wait up to 10 s, in order, then
  count as `unresolved`. A rescan every 30 s prunes vanished cgroups.
- **Output.** Buffered, flushed at most 40 ms after the last write (an event reaches the file in < 100 ms).
  Every 5 s the sensor also replaces (tmp + rename) `$SENSOR_STATS_PATH` (default `/var/run/kubeheal/sensor-stats.json`, same emptyDir)
  with `{events_total, drops_total, pool_full_total, lost_total, cgroups, uptime_s, ts_ms}`; the security agent exports it as `kubeheal_sensor_*`.
  SIGTERM/SIGINT drain the ring buffer, flush and print final stats. `evt.time` = boottime stamp + realtime offset
  (re-read every second).

| Falco field | Sensor |
|---|---|
| `evt.type` | open, openat, openat2, creat, rename, renameat, renameat2, unlink, unlinkat, truncate, ftruncate, chmod, fchmod, fchmodat (by syscall number; io_uring / fchmodat2 get the hook's generic name) |
| `evt.arg.flags` | opens: `O_RDONLY`/`O_WRONLY`/`O_RDWR` + `O_CREAT`, `O_TRUNC`, `O_APPEND` |
| `fd.name` | opens, ftruncate, fchmod |
| `fs.path.source` / `fs.path.target` | rename old / new path |
| `fs.path.name` | unlink, truncate, chmod, fchmodat |
| `proc.pid` | host tgid |
| `container.id`, `k8s.pod.uid`, `k8s.ns.name`, `k8s.pod.name` | cgroup tree + `/var/log/pods` |

## Privileges

uid 0 with `drop: [ALL]`, `add: [BPF, PERFMON]`, `readOnlyRootFilesystem`, no hostPID. No SYS_ADMIN (attach is a BPF
link) and no SYS_RESOURCE (kernel >= 5.11 charges BPF memory to the memcg: the ring buffer counts against the
container's memory limit). Mounts: the events emptyDir (rw), host `/sys/fs/cgroup` (ro), `/var/log/pods` (ro).
Kernel needs: BTF (`/sys/kernel/btf/vmlinux`), `bpf_loop` (5.17+); x86_64 or arm64 (syscall number read from `orig_ax` / `syscallno`).
Per-platform kernel notes (BPF LSM, managed node images): `docs/operations.md` "Platforms".

## Build and test

The BPF object is compiled per target arch (`build.rs`: `-D__TARGET_ARCH_x86|arm64`, `-I/usr/include/<triple>`; the bpf target itself is arch-neutral).
Native `cargo build` on arm64 hosts works the same; cross: `rustup target add aarch64-unknown-linux-gnu` + `gcc-aarch64-linux-gnu`, `libelf-dev:arm64`, `zlib1g-dev:arm64` (the Dockerfile shows the exact environment).


    cd sensor && CARGO_BUILD_JOBS=4 nice -n 10 cargo build --release && cargo test --release
    uv run --all-extras pytest sensor/tests       # every --selftest-json line through parse_line + SYSCALL_GROUPS
    minikube image build -t kubeheal.invalid/sensor:v5 sensor/   # install.sh does this
    docker buildx build --platform linux/amd64,linux/arm64 sensor/   # multi-arch; the compile is a cross build, no QEMU
    docker buildx build --target clippy --platform linux/arm64 sensor/            # clippy -D warnings, aarch64
    docker buildx build --target test-bin --platform linux/arm64 -o out sensor/   # unit tests; run under QEMU (see Dockerfile)

Flags: `--prefix` (1-4), `--exclude-ns`, `--output`, `--cgroup-root`, `--pod-logs-dir`, `--stats-secs` (default 60),
`--all-cgroups` (debug: every process), `--selftest-json` (fixture lines, no BPF).

## Measured (minikube, kernel 7.3.1 CachyOS, 12 CPUs, 2026-11-08)

khe-perf/ioload (write tmp, rename, read; RATE 500 per pod), lag sampled every 2 s for 30 s:

| | Falco (before) | sensor, 10 pods | sensor, 20 pods |
|---|---|---|---|
| events/s | capped ~1900 | ~7000 | ~6400 (node CPU saturated) |
| event lag (newest line) | grows ~0.8 s/s | 3-41 ms | <= 40 ms (first samples; apiserver then unreachable) |
| agent read lag | minutes | <= 0.25 s | - |
| event-source CPU | ~1.7-2 cores | 0.14-0.30 cores | 0.22 cores |
| security-agent CPU | - | 0.37-0.43 cores | 0.46 cores |
| lost | Falco drops | 0 | 0 ring drops, 2 pool_full (pool then 8 slots; 32 now) |

## Limits

- x86_64 and arm64 (arm64 has no `open`/`creat`/`rename`/`unlink`/`chmod` syscalls; `evt.type` is the `*at` name). Not run on a real arm64 kernel yet. rmdir/mkdir, link/symlink, chown, xattrs, mmap writes are not hooked
  (the model does not use them).
- An open is reported after the LSM check; a later failure inside the filesystem's `->open` still shows.
- With `fexit/` only (no bpf LSM), inlined hooks are blind: the startup line says which.
- If the agent stops reading, the events file grows on the emptyDir (node disk) without bound, as with Falco.
