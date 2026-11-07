//! Ring-buffer record -> Falco json_output line (the shape agents/security_agent/falco.py parse_line reads).
use serde_json::{json, Value};

pub const EV_SIZE: usize = 544;
const PLEN: usize = 256;

#[derive(Clone, Debug, Default)]
pub struct Rec {
    pub ts: u64, // CLOCK_BOOTTIME ns
    pub cgid: u64,
    pub pid: u32,
    pub nr: u32,
    pub flags: u32,
    #[allow(dead_code)]
    pub group: u32,
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
    /// Layout of `struct ev` in sensor.bpf.c.
    pub fn parse(b: &[u8]) -> Option<Rec> {
        if b.len() < EV_SIZE {
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
            group: u32_at(28),
            path: cstr(&b[32..32 + PLEN]),
            new_path: cstr(&b[32 + PLEN..32 + 2 * PLEN]),
        })
    }
}

/// x86_64 syscall number -> Falco evt.type (fchmodat2 is reported as fchmodat: the model has no separate name).
pub fn evt_type(nr: u32) -> Option<&'static str> {
    Some(match nr {
        2 => "open", 257 => "openat", 437 => "openat2", 85 => "creat",
        82 => "rename", 264 => "renameat", 316 => "renameat2",
        87 => "unlink", 263 => "unlinkat", 76 => "truncate",
        90 => "chmod", 268 | 452 => "fchmodat",
        _ => return None,
    })
}

/// Falco puts the opened path in fd.name, rename old/new in fs.path.source/target, other path calls in fs.path.name.
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

pub fn to_json(r: &Rec, p: &Pod, boot_to_epoch_ns: u64) -> Option<String> {
    let t = evt_type(r.nr)?;
    let epoch = r.ts + boot_to_epoch_ns;
    let mut f = json!({
        "evt.type": t, "evt.time": epoch, "proc.pid": r.pid,
        "container.id": p.cid, "k8s.ns.name": p.ns, "k8s.pod.name": p.name, "k8s.pod.uid": p.uid,
    });
    let m = f.as_object_mut().unwrap();
    match t {
        "open" | "openat" | "openat2" | "creat" => {
            m.insert("evt.arg.flags".into(), Value::String(flag_names(r.flags))); // Falco text; open_syscall() reads names
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

/// Keep at most 4 non-empty prefixes of at most 63 bytes (kernel map slots); an over-long one is an error, not truncated.
pub fn clean_prefixes(v: &[String]) -> Result<Vec<String>, String> {
    let v: Vec<String> = v.iter().filter(|s| !s.is_empty()).cloned().collect();
    if v.is_empty() || v.len() > 4 {
        return Err("need 1-4 non-empty --prefix values".into());
    }
    if let Some(s) = v.iter().find(|s| s.len() > 63) {
        return Err(format!("prefix longer than 63 bytes: {s}"));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod() -> Pod {
        Pod { ns: "demo".into(), name: "web-0".into(), uid: "u-1".into(), cid: "abc".into() }
    }

    #[test]
    fn prefixes() {
        assert!(clean_prefixes(&["/data/".into(), "".into()]).is_ok());
        assert!(clean_prefixes(&[]).is_err());
        assert!(clean_prefixes(&["x".repeat(64)]).is_err());
        assert!(clean_prefixes(&vec!["/a".to_string(); 5]).is_err());
    }

    #[test]
    fn rename_and_open_json() {
        let r = Rec { ts: 5, nr: 316, pid: 7, path: "/data/a".into(), new_path: "/data/a.locked".into(), ..Default::default() };
        let v: Value = serde_json::from_str(&to_json(&r, &pod(), 1000).unwrap()).unwrap();
        let f = &v["output_fields"];
        assert_eq!(f["evt.type"], "renameat2");
        assert_eq!(f["fs.path.target"], "/data/a.locked");
        assert_eq!(f["evt.time"], 1005);
        let o = Rec { nr: 257, flags: 0o101, path: "/data/x".into(), ..Default::default() };
        let v: Value = serde_json::from_str(&to_json(&o, &pod(), 0).unwrap()).unwrap();
        assert_eq!(v["output_fields"]["evt.arg.flags"], "O_WRONLY|O_CREAT");
    }

    #[test]
    fn parse_record() {
        let mut b = vec![0u8; EV_SIZE];
        b[20..24].copy_from_slice(&87u32.to_le_bytes());
        b[32..38].copy_from_slice(b"/data/");
        let r = Rec::parse(&b).unwrap();
        assert_eq!((r.nr, r.path.as_str()), (87, "/data/"));
        assert!(Rec::parse(&b[..10]).is_none());
    }
}
