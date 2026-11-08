mod pods;
mod render;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use render::{clean_prefixes, group, to_json, Pod, Rec, GROUPS};
use std::{
    cell::RefCell,
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd},
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

mod skel {
    include!(concat!(env!("OUT_DIR"), "/sensor.skel.rs"));
}
use skel::*;

/// Records of a cgroup not yet resolvable to a pod wait this long (the pod's log dir or cgroup appears late), then drop.
const PENDING_FOR: Duration = Duration::from_secs(10);
const PENDING_MAX: usize = 1 << 16;
/// An event reaches the output file at most this long (+ one poll) after the ring buffer saw it.
const FLUSH_EVERY: Duration = Duration::from_millis(40);

#[derive(Parser)]
#[command(about = "KubeHeal eBPF file-activity sensor; writes Falco-shaped JSON lines")]
struct Args {
    /// Watched path prefix, as seen inside the container (1-4 times, absolute, <=63 bytes; end with / for a directory)
    #[arg(long, default_value = "/data/")]
    prefix: Vec<String>,
    /// Namespace whose pods are never reported (filtered in the kernel once the pod is resolved)
    #[arg(long, default_value = "kubeheal")]
    exclude_ns: Vec<String>,
    /// Append events to this file (the security agent's FALCO_EVENTS_PATH); default stdout
    #[arg(long)]
    output: Option<PathBuf>,
    /// Debug: skip the pod/cgroup filter and attribute events to a fake pod
    #[arg(long)]
    all_cgroups: bool,
    /// Host cgroup v2 mount
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_root: PathBuf,
    /// Kubelet pod log directory (KubeletConfiguration podLogsDir)
    #[arg(long, default_value = "/var/log/pods")]
    pod_logs_dir: PathBuf,
    /// Seconds between stats lines on stderr (0 = only at exit)
    #[arg(long, default_value_t = 60)]
    stats_secs: u64,
    /// Print one fixture line per event kind and exit (no BPF, no root)
    #[arg(long)]
    selftest_json: bool,
}

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn boot_to_epoch_ns() -> u64 {
    let ns = |c| {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(c, &mut t) };
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    };
    ns(libc::CLOCK_REALTIME) - ns(libc::CLOCK_BOOTTIME)
}

fn selftest() {
    use render::*;
    let pod = Pod { ns: "demo".into(), name: "web-0".into(), uid: "11111111-2222-3333-4444-555555555555".into(), cid: "c".repeat(64) };
    let cases = [
        (K_OPEN, 2, 0o100000), (K_OPEN, 257, 0), (K_OPEN, 257, 0o101), (K_OPEN, 437, 0o2), (K_OPEN, 85, 0o1101), (K_OPEN, 257, 0o1000),
        (K_RENAME, 82, 0), (K_RENAME, 264, 0), (K_RENAME, 316, 0),
        (K_UNLINK, 87, 0), (K_UNLINK, 263, 0), (K_TRUNCATE, 76, 0), (K_FTRUNCATE, 77, 0),
        (K_CHMOD, 90, 0), (K_CHMOD, 91, 0), (K_CHMOD, 268, 0), (K_CHMOD, 452, 0),
    ];
    for (kind, nr, flags) in cases {
        let new_path = if kind == K_RENAME { "/data/f.txt.locked".into() } else { String::new() };
        let r = Rec { ts: 1_000, cgid: 1, pid: 42, nr, flags, kind, path: "/data/f.txt".into(), new_path };
        println!("{}", to_json(&r, &pod, 1_700_000_000_000_000_000).unwrap());
    }
}

/// Lost events: ring buffer full, walk pool exhausted (all CPUs), fexit runs skipped by the kernel's recursion guard.
fn lost(skel: &SensorSkel) -> (u64, u64, u64) {
    let drop = |k: u32| match skel.maps.drops.lookup_percpu(&k.to_ne_bytes(), MapFlags::ANY) {
        Ok(Some(v)) => v.iter().map(|c| u64::from_ne_bytes(c[..8].try_into().unwrap())).sum(),
        _ => 0,
    };
    let misses = skel
        .object()
        .progs()
        .map(|p| {
            let mut info = libbpf_sys::bpf_prog_info::default();
            let mut len = std::mem::size_of_val(&info) as u32;
            let ok = unsafe { libbpf_sys::bpf_prog_get_info_by_fd(p.as_fd().as_raw_fd(), &mut info, &mut len) } == 0;
            if ok { info.recursion_misses } else { 0 }
        })
        .sum();
    (drop(0), drop(1), misses)
}

fn load<'o>(obj: &'o mut MaybeUninit<libbpf_rs::OpenObject>, a: &Args, prefixes: &[String], lsm: bool) -> Result<SensorSkel<'o>> {
    let mut open = SensorSkelBuilder::default().open(obj).context("open bpf object")?;
    let ro = open.maps.rodata_data.as_deref_mut().context("rodata")?;
    ro.all_cgroups = a.all_cgroups as u8;
    ro.self_pid = std::process::id();
    let ns = std::fs::metadata("/proc/self/ns/pid").context("stat /proc/self/ns/pid")?;
    (ro.self_ns_dev, ro.self_ns_ino) = (std::os::unix::fs::MetadataExt::dev(&ns), std::os::unix::fs::MetadataExt::ino(&ns));
    for (slot, p) in ro.pfx.iter_mut().zip(prefixes) {
        slot.len = p.len() as u32;
        for (d, s) in slot.s.iter_mut().zip(p.bytes()) {
            *d = s as _;
        }
    }
    if !lsm {
        let p = &mut open.progs;
        for prog in [&mut p.lsm_open, &mut p.lsm_rename, &mut p.lsm_unlink, &mut p.lsm_truncate, &mut p.lsm_ftruncate, &mut p.lsm_chmod] {
            prog.set_autoload(false);
        }
    }
    Ok(open.load()?)
}

/// One write of each hooked kind on a scratch file, by this process.
fn exercise(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
    let (f1, f2) = (dir.join(".kubeheal-sensor-selftest"), dir.join(".kubeheal-sensor-selftest.2"));
    let f = OpenOptions::new().create(true).write(true).truncate(false).open(&f1)?; // file_open
    f.set_len(1)?; // file_truncate
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?; // path_chmod
    drop(f);
    let c = std::ffi::CString::new(f1.as_os_str().as_bytes()).unwrap();
    if unsafe { libc::truncate(c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error()); // path_truncate
    }
    std::fs::rename(&f1, &f2)?; // path_rename
    std::fs::remove_file(&f2) // path_unlink
}

/// Attach both variants of every hook, run the self-test, keep per hook the lsm/ program if it saw the test, else
/// the fexit/ one. A hook neither saw is reported (its operations would be missed) and keeps fexit/.
fn attach_hooks(skel: &mut SensorSkel, dir: &std::path::Path) -> Result<Vec<libbpf_rs::Link>> {
    const H: [&str; 6] = ["open", "rename", "unlink", "truncate", "ftruncate", "chmod"]; // enum H_* in sensor.bpf.c
    let p = &skel.progs;
    let pairs = [(&p.lsm_open, &p.fx_open), (&p.lsm_rename, &p.fx_rename), (&p.lsm_unlink, &p.fx_unlink),
        (&p.lsm_truncate, &p.fx_truncate), (&p.lsm_ftruncate, &p.fx_ftruncate), (&p.lsm_chmod, &p.fx_chmod)];
    let links: Vec<_> = pairs.iter().map(|(l, f)| (l.attach().ok(), f.attach().ok())).collect();
    let bss = skel.maps.bss_data.as_deref_mut().context("bss")?;
    unsafe { std::ptr::write_volatile(&mut bss.testing, 1) };
    let tested = exercise(dir);
    unsafe { std::ptr::write_volatile(&mut bss.testing, 0) };
    tested.with_context(|| format!("hook self-test in {}", dir.display()))?;
    let seen = unsafe { std::ptr::read_volatile(&bss.seen) };
    let (mut keep, mut via, mut blind) = (Vec::new(), Vec::new(), Vec::new());
    for (i, (l, f)) in links.into_iter().enumerate() {
        let (name, link) = match (seen[0][i] != 0 && l.is_some(), seen[1][i] != 0) {
            (true, _) => ("lsm", l),
            (false, true) => ("fexit", f),
            _ => {
                blind.push(H[i]);
                ("none", f)
            }
        };
        via.push(format!("{}={name}", H[i]));
        keep.extend(link);
    }
    eprintln!("kubeheal-sensor: hooks {}", via.join(" "));
    if !blind.is_empty() {
        eprintln!("kubeheal-sensor: WARNING no hook observed {blind:?}: those operations are not reported (enable lsm=...,bpf)");
    }
    Ok(keep)
}

fn main() -> Result<()> {
    let a = Args::parse();
    if a.selftest_json {
        selftest();
        return Ok(());
    }
    let prefixes = clean_prefixes(&a.prefix).map_err(anyhow::Error::msg)?;
    for s in [libc::SIGTERM, libc::SIGINT] {
        unsafe { libc::signal(s, on_signal as *const () as libc::sighandler_t) };
    }

    let (mut o1, mut o2) = (MaybeUninit::uninit(), MaybeUninit::uninit());
    let mut skel = match load(&mut o1, &a, &prefixes, true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kubeheal-sensor: lsm/ programs not loadable ({e:#}); fexit/ only");
            load(&mut o2, &a, &prefixes, false).context("load bpf (needs CAP_BPF + CAP_PERFMON, kernel BTF)")?
        }
    };
    // Kept open for the program's lifetime: the CGROUP_ARRAY holds a reference to the cgroup, not the fd.
    let _kubepods: Option<File> = if a.all_cgroups {
        None
    } else {
        let dir = pods::kubepods_dir(&a.cgroup_root).with_context(|| format!("no kubepods cgroup under {}", a.cgroup_root.display()))?;
        let f = File::open(&dir).with_context(|| format!("open {}", dir.display()))?;
        skel.maps.kubepods.update(&0u32.to_ne_bytes(), &f.as_raw_fd().to_ne_bytes(), MapFlags::ANY).context("kubepods cgroup map")?;
        eprintln!("kubeheal-sensor: pods under {}, prefixes {prefixes:?}, excluding namespaces {:?}", dir.display(), a.exclude_ns);
        Some(f)
    };

    let batch: Rc<RefCell<Vec<Rec>>> = Rc::default();
    let mut rb = RingBufferBuilder::new();
    {
        let batch = batch.clone();
        rb.add(&skel.maps.rb, move |b: &[u8]| {
            if let Some(r) = Rec::parse(b) {
                batch.borrow_mut().push(r);
            }
            0
        })?;
    }
    let rb = rb.build()?;
    let selftest_dir = a.output.as_ref().and_then(|p| p.parent()).map_or_else(std::env::temp_dir, |p| p.to_path_buf());
    let _links = attach_hooks(&mut skel, &selftest_dir)?;

    let sink: Box<dyn Write> = match &a.output {
        Some(p) => Box::new(OpenOptions::new().create(true).append(true).open(p).with_context(|| format!("open {}", p.display()))?),
        None => Box::new(std::io::stdout().lock()),
    };
    let mut out = BufWriter::with_capacity(1 << 20, sink);
    let fake = Pod { ns: "debug".into(), name: "all-cgroups".into(), uid: "00000000-0000-0000-0000-000000000000".into(), cid: String::new() };
    let mut res = pods::Resolver::new(a.cgroup_root.clone(), a.pod_logs_dir.clone());
    let (mut skipped, mut synced) = (HashSet::<u64>::new(), u64::MAX);
    let mut pending: Vec<(Rec, Instant)> = Vec::new();
    let (mut counts, mut unresolved) = ([0u64; 6], 0u64);
    let mut off = boot_to_epoch_ns();
    let start = Instant::now();
    let (mut last_flush, mut last_clock, mut last_prune, mut last_stat) = (start, start, start, start);
    let mut dirty = false;

    let stats = |skel: &SensorSkel, counts: &[u64; 6], unresolved: u64, pending: usize, pods: usize| {
        let (drops, pool_full, misses) = lost(skel);
        let g: Vec<String> = GROUPS.iter().zip(counts).map(|(n, c)| format!("{n}={c}")).collect();
        eprintln!("kubeheal-sensor stats: emitted={} {} drops={drops} pool_full={pool_full} recursion_misses={misses} unresolved={unresolved} pending={pending} pod_cgroups={pods}",
            counts.iter().sum::<u64>(), g.join(" "));
    };

    loop {
        let stop = STOP.load(Ordering::Relaxed);
        if stop {
            rb.consume().ok(); // whatever the kernel already queued
        } else if let Err(e) = rb.poll(Duration::from_millis(20)) {
            if e.kind() != libbpf_rs::ErrorKind::Interrupted {
                bail!("ringbuf poll: {e}");
            }
        }
        let now = Instant::now();
        let fresh = std::mem::take(&mut *batch.borrow_mut());
        if !(pending.is_empty() && fresh.is_empty()) {
            // pending first and `held` cgroups stay held: a pod's events keep their order
            let mut held = HashSet::new();
            let mut keep = Vec::new();
            for (r, t) in std::mem::take(&mut pending).into_iter().chain(fresh.into_iter().map(|r| (r, now))) {
                let p = if a.all_cgroups { Some(&fake) } else if held.contains(&r.cgid) { None } else { res.get(r.cgid) };
                match p {
                    Some(p) if a.exclude_ns.contains(&p.ns) => {}
                    Some(p) => {
                        if let Some(l) = to_json(&r, p, off) {
                            writeln!(out, "{l}")?;
                            counts[group(&r)] += 1;
                            dirty = true;
                        }
                    }
                    None if now - t < PENDING_FOR && keep.len() < PENDING_MAX && !stop => {
                        held.insert(r.cgid);
                        keep.push((r, t));
                    }
                    None => unresolved += 1,
                }
            }
            pending = keep;
        }
        if dirty && (stop || now - last_flush >= FLUSH_EVERY) {
            out.flush()?;
            dirty = false;
            last_flush = now;
        }
        if !a.all_cgroups && now - last_prune >= Duration::from_secs(30) {
            res.rescan();
            last_prune = now;
        }
        if res.scans != synced {
            // kernel-side namespace exclusion; cgroups gone from the tree leave the map
            let want: HashSet<u64> = res.pods().iter().filter(|(_, p)| a.exclude_ns.contains(&p.ns)).map(|(id, _)| *id).collect();
            for id in skipped.difference(&want) {
                let _ = skel.maps.skip.delete(&id.to_ne_bytes());
            }
            for id in want.difference(&skipped) {
                skel.maps.skip.update(&id.to_ne_bytes(), &[1u8], MapFlags::ANY)?;
            }
            (skipped, synced) = (want, res.scans);
        }
        if now - last_clock >= Duration::from_secs(1) {
            off = boot_to_epoch_ns(); // follows NTP steps of the realtime clock
            last_clock = now;
        }
        if stop {
            break;
        }
        if a.stats_secs > 0 && now - last_stat >= Duration::from_secs(a.stats_secs) {
            stats(&skel, &counts, unresolved, pending.len(), res.pods().len());
            last_stat = now;
        }
    }
    stats(&skel, &counts, unresolved, pending.len(), res.pods().len());
    Ok(())
}
