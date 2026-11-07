# kubeheal-sensor (Tier 3 prototype)

eBPF replacement for Falco's ingestion: one `raw_syscalls/sys_enter` program filters in the kernel
(pod cgroup + path prefix) and ships compact records through a ring buffer. Userspace prints
Falco-shaped JSON lines, so the Python security agent consumes it unchanged
(`FALCO_EVENTS_PATH=<sensor output file>`, same `parse_line`, same features).

## Build

Needs clang, libelf, zlib, libbpf headers (`/usr/include/bpf`), cargo. No bpftool/vmlinux.h: the program reads
only the stable tracepoint context and x86_64 syscall ABI.

    cd sensor && CARGO_BUILD_JOBS=2 nice -n 19 cargo build --release
    cargo test --release && uv run pytest sensor/tests

## Run (root or CAP_BPF + CAP_PERFMON + CAP_SYS_RESOURCE; needs host cgroup v2 and /var/lib/kubelet)

    kubeheal-sensor --prefix /data/ > /var/run/falco/events.jsonl      # pods only
    kubeheal-sensor --all-cgroups --prefix /tmp/kh-sensor-test/        # debug, every process
    kubeheal-sensor --selftest-json                                    # fixture lines, no BPF, no root

Flags: `--prefix` (1-4, <=63 bytes, absolute), `--cgroup-root`, `--kubelet-dir`, `--rescan-secs`, `--stats-secs`
(per-cgroup per-group counters from the BPF map, printed to stderr; always dumped at exit).

## Output -> Falco fields

| Falco field | Sensor |
|---|---|
| `evt.type` | open, openat, openat2, creat, rename, renameat, renameat2, unlink, unlinkat, truncate, chmod, fchmodat (fchmodat2 -> fchmodat) |
| `evt.arg.flags` | open flags as Falco text, e.g. `O_WRONLY\|O_CREAT` (opens only; creat = O_WRONLY\|O_CREAT\|O_TRUNC) |
| `fd.name` | opened path (opens) |
| `fs.path.source` / `fs.path.target` | rename old / new path |
| `fs.path.name` | path of unlink/truncate/chmod |
| `proc.pid` | tgid |
| `evt.time` | epoch ns (boottime stamp + boot-to-realtime offset taken at start) |
| `container.id`, `k8s.pod.uid` | from the cgroup directory names |
| `k8s.ns.name`, `k8s.pod.name` | `/var/lib/kubelet/pods/<uid>/` : `etc-hosts` hostname and the projected service-account `namespace` file |

## Known limits

- x86_64 syscall numbers only (arm64 needs another table).
- Entry-only: failed syscalls are reported too (Falco reports on exit).
- Runtime trial (minikube, kernel 7.3, x86_64, 2026-11-07): the program passed the verifier first try and attached; no program change needed.
  Attribution (ns/pod/uid/container id) correct for open/rename/unlink/chmod/O_TRUNC; `parse_line` accepts every emitted line.
  Relative paths confirmed missed (`cd /tmp; echo > rel.txt` emits nothing); dirfd-relative `openat`/`unlinkat` are the same case. Fixing needs
  all relative paths shipped from pod cgroups plus `/proc/<pid>/{cwd,fd/<n>}` resolution in userspace (racy, noisy): not done.
- Trial manifest: `deploy/trial-daemonset.yaml` (privileged, hostPID, hostPath cgroup/kubelet/bpffs/btf/debugfs/tracefs; kubelet mount needs
  `mountPropagation: HostToContainer` or the projected SA `namespace` files are invisible and every pod stays unresolved; tracefs is needed to attach).
  Image: `minikube image build -t kubeheal-sensor:trial sensor/` (runtime base debian-slim: libbpf-sys links libelf/zlib dynamically).

## Known gaps (prototype)

- Pod resolution uses the projected SA volume + etc-hosts (`src/pods.rs:171-177`): pods with `automountServiceAccountToken: false` and hostNetwork pods are invisible; the name is wrong for StatefulSet subdomain / hostAliases / `spec.hostname` / names over 63 chars. Fix: resolve uid -> ns/name from the API (watch pods with `fieldSelector spec.nodeName`).
- Raw-argument prefix match (`sensor.bpf.c:57-73,88-93`): relative / dirfd paths are missed, `/./data` evades the filter, `/data/../etc` matches falsely, paths over 255 bytes are cut silently. Fix: fentry/LSM on `security_file_open` / `security_path_{rename,unlink,truncate,chmod}` / `security_file_truncate`, with `bpf_d_path` or a bounded d_parent walk. This also covers `ftruncate` and `fchmod` (fd only, not hooked today).
- Ring-buffer reserve failure is silent (`sensor.bpf.c:83-85`; 4 MiB buffer). Fix: a per-CPU drops counter in the stats dump.
- New cgroups enter the kernel filter only at the 2 s rescan (`main.rs:229-242`), so a pod can lose its first ~2 s of events. Fix: filter on the kubepods ancestor cgroup and resolve lazily.
- The `counts` map is never pruned (cap 16384), so stats stop after many pods. Fix: delete the counts key together with the cgroups key.
- The trial DaemonSet runs privileged + hostPID and mounts bpffs/btf/debugfs it doesn't need. Fix: drop ALL capabilities, add BPF, PERFMON (+SYS_RESOURCE before kernel 5.11), set `readOnlyRootFilesystem`, keep only the cgroup/kubelet/tracefs mounts.
- No SIGTERM handler (`main.rs:243-246`): buffered output and the final stats are lost on shutdown. Fix: signal-hook flag.
- CPU: `raw_syscalls/sys_enter` runs on every syscall and reserves and reads strings before the prefix test; the pod cache is rebuilt on every scan. Fix: per-syscall tracepoints and a per-CPU scratch buffer, reserve only on a hit; keep the pod cache across scans.
