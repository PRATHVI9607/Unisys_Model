//! cgroup-v2 scan: container cgroup inode (= bpf_get_current_cgroup_id) -> pod identity.
use crate::render::Pod;
use std::{collections::HashMap, fs, os::unix::fs::MetadataExt, path::Path};

/// `kubepods-burstable-pod<uid_with_underscores>.slice` (systemd) or `pod<uid>` (cgroupfs) -> uid.
pub fn pod_uid(dir: &str) -> Option<String> {
    let s = dir.strip_suffix(".slice").unwrap_or(dir);
    let u = s.rsplit_once("-pod").map(|x| x.1).or_else(|| s.strip_prefix("pod"))?;
    (u.len() >= 32).then(|| u.replace('_', "-"))
}

/// `cri-containerd-<id>.scope`, `docker-<id>.scope` or a bare 64-hex dir (cgroupfs) -> container id.
pub fn container_id(dir: &str) -> Option<String> {
    let s = dir.strip_suffix(".scope").unwrap_or(dir);
    let id = s.rsplit('-').next()?;
    (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_string())
}

/// shortcut: name from the kubelet's etc-hosts (last line's hostname), namespace from the projected
/// service-account volume's `namespace` file; pods with neither (automount off, hostNetwork) are not watched.
fn resolve(kubelet: &Path, uid: &str) -> Option<(String, String)> {
    let base = kubelet.join("pods").join(uid);
    let hosts = fs::read_to_string(base.join("etc-hosts")).ok()?;
    let name = hosts.lines().rev().find_map(|l| l.split_whitespace().nth(1))?.to_string();
    let proj = base.join("volumes/kubernetes.io~projected");
    let ns = fs::read_dir(proj).ok()?.flatten().find_map(|d| fs::read_to_string(d.path().join("namespace")).ok())?;
    Some((ns.trim().to_string(), name))
}

fn walk(dir: &Path, uid: Option<&str>, kubelet: &Path, cache: &mut HashMap<String, Option<(String, String)>>, out: &mut HashMap<u64, Pod>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if !md.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if let (Some(uid), Some(cid)) = (uid, container_id(&name)) {
            if let Some((ns, pod)) = cache.entry(uid.to_string()).or_insert_with(|| resolve(kubelet, uid)).clone() {
                out.insert(md.ino(), Pod { ns, name: pod, uid: uid.to_string(), cid });
            }
        } else {
            let u = pod_uid(&name);
            walk(&e.path(), u.as_deref().or(uid), kubelet, cache, out);
        }
    }
}

/// Scan every `kubepods*` top-level cgroup. Unresolved pods are retried on each scan (cache keeps only hits).
pub fn scan(cgroup_root: &Path, kubelet: &Path) -> HashMap<u64, Pod> {
    let mut out = HashMap::new();
    let mut cache = HashMap::new();
    if let Ok(rd) = fs::read_dir(cgroup_root) {
        for e in rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("kubepods")) {
            walk(&e.path(), None, kubelet, &mut cache, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let u = "0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0";
        assert_eq!(pod_uid(&format!("kubepods-burstable-pod{u}.slice")).unwrap(), u.replace('_', "-"));
        assert_eq!(pod_uid("kubepods-burstable.slice"), None);
        let id = "a".repeat(64);
        assert_eq!(container_id(&format!("cri-containerd-{id}.scope")).unwrap(), id);
        assert_eq!(container_id(&id).unwrap(), id);
        assert_eq!(container_id("crio-conmon-short.scope"), None);
    }
}
