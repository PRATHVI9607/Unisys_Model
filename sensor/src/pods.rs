//! Pod identity for a cgroup id: the cgroup-v2 tree gives container cgroup inode (= bpf_get_current_cgroup_id)
//! -> pod uid + container id; the kubelet's pod log directories `<namespace>_<pod>_<uid>` give uid -> namespace
//! and name. The kubelet creates that directory before the pod sandbox starts, for every pod (also
//! automountServiceAccountToken: false and hostNetwork), so no API access is needed.
use crate::render::Pod;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Minimum time between two rescans triggered by an unknown cgroup.
const RESCAN_EVERY: Duration = Duration::from_millis(100);

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

/// Kubelet pod log dir `<namespace>_<pod name>_<uid>` -> (uid, namespace, name). Namespaces and pod names are
/// DNS names, so they never contain `_`.
pub fn log_dir(dir: &str) -> Option<(String, String, String)> {
    let mut it = dir.splitn(3, '_');
    let (ns, name, uid) = (it.next()?, it.next()?, it.next()?);
    (!ns.is_empty() && !name.is_empty() && uid.len() == 36).then(|| (uid.into(), ns.into(), name.into()))
}

/// Every cgroup below a pod's container cgroup (nested ones included) -> (pod uid, container id).
fn walk(dir: &Path, uid: Option<&str>, cid: Option<&str>, out: &mut HashMap<u64, (String, String)>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if !md.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let u = pod_uid(&name).or(uid.map(str::to_string));
        let c = u.as_ref().and_then(|_| container_id(&name)).or(cid.map(str::to_string));
        if let (Some(u), Some(c)) = (&u, &c) {
            out.insert(md.ino(), (u.clone(), c.clone()));
        }
        walk(&e.path(), u.as_deref(), c.as_deref(), out);
    }
}

/// The top-level `kubepods` / `kubepods.slice` cgroup every pod lives under.
pub fn kubepods_dir(cgroup_root: &Path) -> Option<PathBuf> {
    fs::read_dir(cgroup_root).ok()?.flatten().map(|e| e.path()).find(|p| {
        p.is_dir() && p.file_name().is_some_and(|n| n == "kubepods" || n == "kubepods.slice")
    })
}

pub struct Resolver {
    cgroup_root: PathBuf,
    logs_dir: PathBuf,
    pods: HashMap<u64, Pod>,
    last: Option<Instant>,
    pub scans: u64,
}

impl Resolver {
    pub fn new(cgroup_root: PathBuf, logs_dir: PathBuf) -> Self {
        Resolver { cgroup_root, logs_dir, pods: HashMap::new(), last: None, scans: 0 }
    }

    /// Rebuild the cgroup -> pod map; vanished cgroups drop out (the map stays bounded).
    pub fn rescan(&mut self) {
        let mut cg = HashMap::new();
        if let Some(k) = kubepods_dir(&self.cgroup_root) {
            walk(&k, None, None, &mut cg);
        }
        let names: HashMap<String, (String, String)> = fs::read_dir(&self.logs_dir)
            .map(|rd| rd.flatten().filter_map(|e| log_dir(&e.file_name().to_string_lossy())).map(|(u, n, p)| (u, (n, p))).collect())
            .unwrap_or_default();
        self.pods = cg
            .into_iter()
            .filter_map(|(id, (uid, cid))| names.get(&uid).map(|(ns, name)| (id, Pod { ns: ns.clone(), name: name.clone(), uid, cid })))
            .collect();
        self.last = Some(Instant::now());
        self.scans += 1;
    }

    /// Pod of a cgroup; an unknown cgroup triggers a rescan at most every RESCAN_EVERY.
    pub fn get(&mut self, cgid: u64) -> Option<&Pod> {
        if !self.pods.contains_key(&cgid) && self.last.is_none_or(|t| t.elapsed() >= RESCAN_EVERY) {
            self.rescan();
        }
        self.pods.get(&cgid)
    }

    pub fn pods(&self) -> &HashMap<u64, Pod> {
        &self.pods
    }
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
        let uid = u.replace('_', "-");
        assert_eq!(log_dir(&format!("khe-x_web-0.a_{uid}")).unwrap(), (uid.clone(), "khe-x".into(), "web-0.a".into()));
        assert_eq!(log_dir("kube-system_coredns"), None);
    }

    #[test]
    fn resolve_from_dirs() {
        let t = std::env::temp_dir().join(format!("kh-sensor-test-{}", std::process::id()));
        let uid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let cid = "b".repeat(64);
        let c = t.join(format!("cg/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{}.slice/cri-containerd-{cid}.scope", uid.replace('-', "_")));
        fs::create_dir_all(c.join("nested")).unwrap();
        fs::create_dir_all(t.join(format!("logs/demo_web-0_{uid}"))).unwrap();
        let mut r = Resolver::new(t.join("cg"), t.join("logs"));
        for dir in [c.clone(), c.join("nested")] {
            let p = r.get(fs::metadata(&dir).unwrap().ino()).cloned().unwrap();
            assert_eq!((p.ns.as_str(), p.name.as_str(), p.uid.as_str(), p.cid.as_str()), ("demo", "web-0", uid, cid.as_str()));
        }
        assert!(r.get(fs::metadata(t.join("cg/kubepods.slice")).unwrap().ino()).is_none());
        fs::remove_dir_all(&t).unwrap();
    }
}
