//! Stats snapshot for the security agent (it exports Prometheus metrics from it): a small JSON file, replaced atomically.
use serde_json::json;
use std::{io, path::Path};

pub struct Snapshot {
    pub events: u64,
    pub drops: u64,
    pub pool_full: u64,
    pub lost: u64, // drops + pool_full + fexit recursion misses
    pub cgroups: usize,
    pub uptime_s: u64,
    pub ts_ms: u64,
}

/// Write to `<path>.tmp`, then rename over `path`: a reader never sees a partial file.
pub fn write(path: &Path, s: &Snapshot) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let doc = json!({"events_total": s.events, "drops_total": s.drops, "pool_full_total": s.pool_full, "lost_total": s.lost,
        "cgroups": s.cgroups, "uptime_s": s.uptime_s, "ts_ms": s.ts_ms});
    std::fs::write(&tmp, doc.to_string())?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_atomically_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("khs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("sensor-stats.json");
        for n in [1u64, 2] {
            write(&p, &Snapshot { events: n, drops: 3, pool_full: 4, lost: 8, cgroups: 5, uptime_s: 6, ts_ms: 7 }).unwrap();
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            assert_eq!(v["events_total"], n);
            for k in ["drops_total", "pool_full_total", "lost_total", "cgroups", "uptime_s", "ts_ms"] {
                assert!(v[k].is_u64(), "{k}");
            }
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
