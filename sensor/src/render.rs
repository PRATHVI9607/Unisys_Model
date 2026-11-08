//! Ring-buffer record -> Falco json_output line (the shape agents/security_agent/falco.py parse_line reads).
use serde_json::{json, Value};

pub const EV_SIZE: usize = 544; // rename records; the others stop before new_path
const PLEN: usize = 256;
const SHORT: usize = 32 + PLEN;
// `enum` in sensor.bpf.c
pub const K_OPEN: u32 = 0;
pub const K_RENAME: u32 = 1;
pub const K_UNLINK: u32 = 2;
pub const K_TRUNCATE: u32 = 3;
pub const K_FTRUNCATE: u32 = 4;
pub const K_CHMOD: u32 = 5;

#[derive(Clone, Debug, Default)]
pub struct Rec {
    pub ts: u64, // CLOCK_BOOTTIME ns
    pub cgid: u64,
    pub pid: u32,
    pub nr: u32, // x86_64 syscall number (orig_ax) at the hook
    pub flags: u32,
    pub kind: u32,
    pub path: String,
    pub new_path: String,
}

#[derive(Clone, Debug, Default)]
pub struct Pod {
    pub ns: String,
    pub name: String,
    pub uid: String,
    pub cid: String,
}

fn cstr(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
}

impl Rec {
    /// Layout of `struct ev` in sensor.bpf.c (new_path only in full-size records).
    pub fn parse(b: &[u8]) -> Option<Rec> {
        if b.len() < SHORT {
            return None;
        }
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Some(Rec {
            ts: u64_at(0),
            cgid: u64_at(8),
            pid: u32_at(16),
            nr: u32_at(20),
            flags: u32_at(24),
            kind: u32_at(28),
            path: cstr(&b[32..32 + PLEN]),
            new_path: if b.len() >= EV_SIZE { cstr(&b[32 + PLEN..EV_SIZE]) } else { String::new() },
        })
    }
}

/// Hook kind + x86_64 syscall number -> Falco evt.type. Calls from elsewhere (io_uring, fchmodat2) get the
/// kind's generic name; the model only uses the group (kubeheal.features.security.SYSCALL_GROUPS).
pub fn evt_type(kind: u32, nr: u32) -> Option<&'static str> {
    Some(match (kind, nr) {
        (K_OPEN, 2) => "open",
        (K_OPEN, 437) => "openat2",
        (K_OPEN, 85) => "creat",
        (K_OPEN, _) => "openat",
        (K_RENAME, 82) => "rename",
        (K_RENAME, 264) => "renameat",
        (K_RENAME, _) => "renameat2",
        (K_UNLINK, 87) => "unlink",
        (K_UNLINK, _) => "unlinkat",
        (K_TRUNCATE, _) => "truncate",
        (K_FTRUNCATE, _) => "ftruncate",
        (K_CHMOD, 90) => "chmod",
        (K_CHMOD, 91) => "fchmod",
        (K_CHMOD, _) => "fchmodat",
        _ => return None,
    })
}

/// Linux open flags -> Falco-style `O_WRONLY|O_CREAT` (open_syscall() reads names; Falco numbers are PPM-encoded, not Linux).
fn flag_names(f: u32) -> String {
    let mut v = vec![["O_RDONLY", "O_WRONLY", "O_RDWR"][(f & 3).min(2) as usize]];
    for (bit, n) in [(0o100, "O_CREAT"), (0o1000, "O_TRUNC"), (0o2000, "O_APPEND")] {
        if f & bit != 0 {
            v.push(n);
        }
    }
    v.join("|")
}

/// Stats group, as open_syscall() + SYSCALL_GROUPS would count it.
pub fn group(r: &Rec) -> usize {
    match r.kind {
        K_OPEN if r.flags & 3 != 0 || r.flags & 0o1100 != 0 => 1,
        K_OPEN => 0,
        K_RENAME => 2,
        K_UNLINK => 3,
        K_TRUNCATE | K_FTRUNCATE => 4,
        _ => 5,
    }
}
pub const GROUPS: [&str; 6] = ["open_r", "open_w", "rename", "unlink", "truncate", "chmod"];

/// Falco puts an fd's path in fd.name (opens, ftruncate, fchmod), rename old/new in fs.path.source/target,
/// other path calls in fs.path.name.
pub fn to_json(r: &Rec, p: &Pod, boot_to_epoch_ns: u64) -> Option<String> {
    let t = evt_type(r.kind, r.nr)?;
    let mut f = json!({
        "evt.type": t, "evt.time": r.ts + boot_to_epoch_ns, "proc.pid": r.pid,
        "container.id": p.cid, "k8s.ns.name": p.ns, "k8s.pod.name": p.name, "k8s.pod.uid": p.uid,
    });
    let m = f.as_object_mut().unwrap();
    match t {
        "open" | "openat" | "openat2" | "creat" => {
            m.insert("evt.arg.flags".into(), Value::String(flag_names(r.flags)));
            m.insert("fd.name".into(), r.path.clone().into());
        }
        "ftruncate" | "fchmod" => {
            m.insert("fd.name".into(), r.path.clone().into());
        }
        "rename" | "renameat" | "renameat2" => {
            m.insert("fs.path.source".into(), r.path.clone().into());
            m.insert("fs.path.target".into(), r.new_path.clone().into());
        }
        _ => {
            m.insert("fs.path.name".into(), r.path.clone().into());
        }
    }
    Some(json!({"rule": "KubeHeal Data File Activity", "priority": "Notice", "output_fields": f}).to_string())
}

/// 1-4 absolute prefixes of at most 63 bytes (kernel rodata slots), compared on the resolved path;
/// an over-long one is an error, not truncated.
pub fn clean_prefixes(v: &[String]) -> Result<Vec<String>, String> {
    let v: Vec<String> = v.iter().filter(|s| !s.is_empty()).cloned().collect();
    if v.is_empty() || v.len() > 4 {
        return Err("need 1-4 non-empty --prefix values".into());
    }
    if let Some(s) = v.iter().find(|s| s.len() > 63 || !s.starts_with('/')) {
        return Err(format!("prefix must be absolute and at most 63 bytes: {s}"));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod() -> Pod {
        Pod { ns: "demo".into(), name: "web-0".into(), uid: "u-1".into(), cid: "abc".into() }
    }

    fn fields(r: &Rec) -> Value {
        let v: Value = serde_json::from_str(&to_json(r, &pod(), 1000).unwrap()).unwrap();
        v["output_fields"].clone()
    }

    #[test]
    fn prefixes() {
        assert!(clean_prefixes(&["/data/".into(), "".into()]).is_ok());
        assert!(clean_prefixes(&[]).is_err());
        assert!(clean_prefixes(&["/".to_string() + &"x".repeat(63)]).is_err());
        assert!(clean_prefixes(&["data/".into()]).is_err());
        assert!(clean_prefixes(&vec!["/a".to_string(); 5]).is_err());
    }

    #[test]
    fn rename_and_open_json() {
        let f = fields(&Rec { ts: 5, kind: K_RENAME, nr: 316, pid: 7, path: "/data/a".into(), new_path: "/data/a.locked".into(), ..Default::default() });
        assert_eq!((f["evt.type"].as_str(), f["fs.path.source"].as_str()), (Some("renameat2"), Some("/data/a")));
        assert_eq!((f["fs.path.target"].as_str(), f["evt.time"].as_u64()), (Some("/data/a.locked"), Some(1005)));
        let f = fields(&Rec { kind: K_OPEN, nr: 257, flags: 0o101, path: "/data/x".into(), ..Default::default() });
        assert_eq!((f["evt.arg.flags"].as_str(), f["fd.name"].as_str()), (Some("O_WRONLY|O_CREAT"), Some("/data/x")));
        let f = fields(&Rec { kind: K_OPEN, nr: 2, flags: 0o100000, path: "/data/x".into(), ..Default::default() });
        assert_eq!((f["evt.type"].as_str(), f["evt.arg.flags"].as_str()), (Some("open"), Some("O_RDONLY")));
    }

    #[test]
    fn kinds_map_to_falco_fields() {
        let ty = |kind, nr| evt_type(kind, nr).unwrap();
        assert_eq!([ty(K_OPEN, 426), ty(K_OPEN, 85), ty(K_UNLINK, 87), ty(K_UNLINK, 263)], ["openat", "creat", "unlink", "unlinkat"]);
        assert_eq!([ty(K_CHMOD, 90), ty(K_CHMOD, 91), ty(K_CHMOD, 452), ty(K_FTRUNCATE, 77)], ["chmod", "fchmod", "fchmodat", "ftruncate"]);
        assert!(evt_type(9, 0).is_none());
        let f = fields(&Rec { kind: K_FTRUNCATE, nr: 77, path: "/data/t".into(), ..Default::default() });
        assert_eq!((f["fd.name"].as_str(), f.get("fs.path.name")), (Some("/data/t"), None));
        let f = fields(&Rec { kind: K_CHMOD, nr: 268, path: "/data/c".into(), ..Default::default() });
        assert_eq!(f["fs.path.name"].as_str(), Some("/data/c"));
        assert_eq!(group(&Rec { kind: K_OPEN, flags: 0o1000, ..Default::default() }), 1); // O_RDONLY|O_TRUNC writes
        assert_eq!(group(&Rec { kind: K_OPEN, flags: 0o200000, ..Default::default() }), 0); // O_DIRECTORY reads
    }

    #[test]
    fn parse_record() {
        let mut b = vec![0u8; EV_SIZE];
        b[20..24].copy_from_slice(&87u32.to_le_bytes());
        b[28..32].copy_from_slice(&K_UNLINK.to_le_bytes());
        b[32..38].copy_from_slice(b"/data/");
        b[32 + PLEN..32 + PLEN + 2].copy_from_slice(b"/n");
        let r = Rec::parse(&b).unwrap();
        assert_eq!((r.nr, r.kind, r.path.as_str(), r.new_path.as_str()), (87, K_UNLINK, "/data/", "/n"));
        assert!(Rec::parse(&b[..10]).is_none());
        let r = Rec::parse(&b[..SHORT]).unwrap();
        assert_eq!((r.path.as_str(), r.new_path.as_str()), ("/data/", ""));
    }
}
