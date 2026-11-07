mod pods;
mod render;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use render::{clean_prefixes, to_json, Pod, Rec};
use std::{
    cell::RefCell, collections::HashMap, io::Write, mem::MaybeUninit, path::PathBuf, rc::Rc, time::{Duration, Instant},
};

mod skel {
    include!(concat!(env!("OUT_DIR"), "/sensor.skel.rs"));
}
use skel::*;

#[derive(Parser)]
#[command(about = "KubeHeal eBPF file-activity sensor; prints Falco-shaped JSON lines on stdout")]
struct Args {
    /// Watched path prefix (1-4 times, <=63 bytes, absolute paths only: compared on the raw syscall argument)
    #[arg(long, default_value = "/data/")]
    prefix: Vec<String>,
    /// Debug: skip the pod/cgroup filter and attribute events to a fake pod
    #[arg(long)]
    all_cgroups: bool,
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup_root: PathBuf,
    #[arg(long, default_value = "/var/lib/kubelet")]
    kubelet_dir: PathBuf,
    /// Seconds between pod/cgroup rescans
    #[arg(long, default_value_t = 2)]
    rescan_secs: u64,
    /// Print one fixture line per captured syscall and exit (no BPF, no root)
    #[arg(long)]
    selftest_json: bool,
    /// Seconds between per-group counter dumps to stderr (0 = only at exit)
    #[arg(long, default_value_t = 0)]
    stats_secs: u64,
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
    let pod = Pod { ns: "demo".into(), name: "web-0".into(), uid: "11111111-2222-3333-4444-555555555555".into(), cid: "c".repeat(64) };
    for (nr, flags) in [(2, 0), (257, 0), (257, 0o101), (437, 0o2), (85, 0o101), (82, 0), (264, 0), (316, 0), (87, 0), (263, 0), (76, 0), (90, 0), (268, 0), (452, 0)] {
        let r = Rec { ts: 1_000, cgid: 1, pid: 42, nr, flags, group: 0, path: "/data/f.txt".into(), new_path: if (82..=82).contains(&nr) || nr == 264 || nr == 316 { "/data/f.txt.locked".into() } else { String::new() } };
        println!("{}", to_json(&r, &pod, 1_700_000_000_000_000_000).unwrap());
    }
}

fn dump(skel: &SensorSkel, pods: &HashMap<u64, Pod>) {
    const G: [&str; 6] = ["open_r", "open_w", "rename", "unlink", "truncate", "chmod"];
    for k in skel.maps.counts.keys() {
        if let Ok(Some(v)) = skel.maps.counts.lookup(&k, MapFlags::ANY) {
            let id = u64::from_ne_bytes(k[..8].try_into().unwrap());
            let n: Vec<String> = (0..6).map(|i| format!("{}={}", G[i], u64::from_ne_bytes(v[i * 8..i * 8 + 8].try_into().unwrap()))).collect();
            eprintln!("cgroup {id} {}: {}", pods.get(&id).map_or("-", |p| p.name.as_str()), n.join(" "));
        }
    }
}

fn main() -> Result<()> {
    let a = Args::parse();
    if a.selftest_json {
        selftest();
        return Ok(());
    }
    let prefixes = clean_prefixes(&a.prefix).map_err(anyhow::Error::msg)?;

    let mut obj = MaybeUninit::uninit();
    let mut open = SensorSkelBuilder::default().open(&mut obj).context("open bpf object")?;
    open.maps.rodata_data.as_mut().context("rodata")?.all_cgroups = a.all_cgroups as u8;
    let skel = open.load().context("load bpf (needs CAP_BPF+CAP_PERFMON or root)")?;

    for (i, p) in prefixes.iter().enumerate() {
        let mut v = vec![0u8; 68]; // struct pfx { u32 len; char s[64]; }
        v[..4].copy_from_slice(&(p.len() as u32).to_ne_bytes());
        v[4..4 + p.len()].copy_from_slice(p.as_bytes());
        skel.maps.pfxs.update(&(i as u32).to_ne_bytes(), &v, MapFlags::ANY)?;
    }

    let known: Rc<RefCell<HashMap<u64, Pod>>> = Rc::default();
    let fake = Pod { ns: "debug".into(), name: "all-cgroups".into(), uid: "00000000-0000-0000-0000-000000000000".into(), cid: String::new() };
    let off = boot_to_epoch_ns();
    let out = Rc::new(RefCell::new(std::io::BufWriter::new(std::io::stdout().lock())));

    let mut rb = RingBufferBuilder::new();
    {
        let (known, out, fake) = (known.clone(), out.clone(), fake.clone());
        let all = a.all_cgroups;
        rb.add(&skel.maps.rb, move |b: &[u8]| {
            let Some(r) = Rec::parse(b) else { return 0 };
            let k = known.borrow();
            let Some(p) = k.get(&r.cgid).or(all.then_some(&fake)) else { return 0 }; // cgroup vanished since the scan
            if let Some(l) = to_json(&r, p, off) {
                let _ = writeln!(out.borrow_mut(), "{l}");
            }
            0
        })?;
    }
    let rb = rb.build()?;
    let _link = skel.progs.on_enter.attach().context("attach tracepoint")?;

    let (mut last_scan, mut last_stat) = (Instant::now() - Duration::from_secs(3600), Instant::now());
    loop {
        if last_scan.elapsed().as_secs() >= a.rescan_secs && !a.all_cgroups {
            let now = pods::scan(&a.cgroup_root, &a.kubelet_dir);
            let mut k = known.borrow_mut();
            for id in k.keys().filter(|id| !now.contains_key(id)) {
                let _ = skel.maps.cgroups.delete(&id.to_ne_bytes());
            }
            for id in now.keys().filter(|id| !k.contains_key(id)) {
                skel.maps.cgroups.update(&id.to_ne_bytes(), &[1u8], MapFlags::ANY)?;
            }
            *k = now;
            last_scan = Instant::now();
        }
        match rb.poll(Duration::from_millis(200)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => break,
            Err(e) => bail!("ringbuf poll: {e}"),
        }
        out.borrow_mut().flush()?;
        if a.stats_secs > 0 && last_stat.elapsed().as_secs() >= a.stats_secs {
            dump(&skel, &known.borrow());
            last_stat = Instant::now();
        }
    }
    dump(&skel, &known.borrow());
    Ok(())
}
