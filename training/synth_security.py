"""Synthetic syscall/entropy windows for the security model.

The default security training set; with `train.py --collected` only its
suspicious/exfiltration windows are used (the lab, training/collect/
security_lab.py, cannot produce those). It is built to be hard rather than
separable by tokens:

- random path roots, file names and extensions; ransomware uses a known
  ransomware extension only sometimes, otherwise a random one or none;
- window lengths 10-512 events (the agent keeps <= MAX_WINDOW_EVENTS per pod),
  window_s from features.security.window_seconds() exactly as the agent computes it, with 0-80 % unrelated background syscalls;
- hard negatives: compressed/encrypted backups, encrypted-at-rest stores
  rewriting files in place, ops scripts (shells, find, chmod, cleanup
  unlinks), gzip log compression
  (write .gz + unlink original), media transcoding (high entropy), log
  rotation and atomic tmp→rename writes (benign renames with extension
  changes), backup uploads (bulk read + network);
- hard negatives that read many originals and write high-entropy files: encrypting
  dedup backups (restic/borg/kopia-like repos: hash-named packs, temp + rename,
  prune unlinks) and package installs (npm/pip: cached tarballs, fresh trees,
  staged renames); originals are never transformed (frac_write_from_read);
- hard positives: in-place encryption without renames, intermittent/partial
  encryption (mid entropy), slow encryption (1-3 files in a long window), and
  trickle encryption at 1-5 files/s caught after 2-12 files;
- windows are cut down to what the live agent can see: only CAPTURED_GROUPS
  syscalls on the data volume (the scenario root) survive, as with the Falco
  rules; at most MAX_ENTROPY_SAMPLES entropy samples (the newest files), missing
  in ~25 % of windows;
- byte counters are pod-wide, as the agent measures them (cgroup io.stat wbytes,
  network-namespace tx bytes): the scenario's bytes (including network and
  writes Falco does not capture) plus background traffic, writes partly still
  in the page cache (writeback lag), unknown (None) in ~25 % of windows.
  Hard negatives here too: backups/compaction write a lot, backup uploads send a
  lot; ransomware writes a lot, exfiltration sends a lot while mostly reading.

Each scenario instance yields 1-4 windows sharing paths and style; its id is
the group, so grouped splits never see the same instance twice. Scores on
this data are not evidence of real-world accuracy (bundle meta marks
`synthetic: true`).
"""

from __future__ import annotations

import numpy as np

from kubeheal.contracts import SECURITY_LABELS
from kubeheal.features.security import (
    CAPTURED_GROUPS,
    MAX_ENTROPY_SAMPLES,
    MAX_WINDOW_EVENTS,
    OPEN_SYSCALLS,
    SYSCALL_GROUPS,
    window_seconds,
)

_READ_CALLS = frozenset({"read", "pread", "pread64", "readv", "preadv", "preadv2"})
_WRITE_CALLS = frozenset({"write", "pwrite", "pwrite64", "writev", "pwritev", "pwritev2"})
CAPTURED = frozenset().union(*(SYSCALL_GROUPS[g] for g in CAPTURED_GROUPS))

ROOTS = ["/data", "/var/lib/app", "/srv/files", "/home/app", "/mnt/volume", "/app/uploads", "/opt/svc/store",
         "/var/www/html", "/tmp/work", "/storage", "/usr/share/app", "/var/lib/postgresql/data"]
WORDS = ["report", "invoice", "user", "image", "export", "data", "config", "notes", "photo", "backup", "order",
         "record", "draft", "table", "chunk", "segment", "asset", "doc", "page", "item"]
DOC_EXT = [".txt", ".csv", ".json", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".sql", ".db", ".xml", ".yaml",
           ".md", ".py", ".html", ".log", ""]
ARCHIVE_EXT = [".gz", ".tar.gz", ".zst", ".zip", ".7z", ".bz2", ".xz", ".gpg", ".enc", ".age"]
MEDIA_EXT = [".mp4", ".webm", ".jpg", ".webp", ".png", ".mp3", ".ogg"]
KNOWN_RANSOM_EXT = [".locked", ".encrypted", ".crypt", ".lockbit", ".akira", ".djvu", ".enc", ".pay"]
NOTES = ["README_DECRYPT.txt", "HOW_TO_RECOVER_FILES.txt", "RESTORE-MY-FILES.html", "!!!_UNLOCK_!!!.txt",
         "_readme_recover.txt", "ransom_note.hta"]
BACKGROUND = ["read", "read", "openat", "mmap", "recvfrom", "sendto", "futex", "epoll_wait", "close", "fstat",
              "write", "connect", "munmap", "clock_gettime", "stat"]
BG_PATHS = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/etc/hosts", "/proc/self/stat", "/dev/null",
            "/etc/resolv.conf", "/usr/lib/python3/dist-packages/x.py", "/sys/fs/cgroup/cpu.max", ""]

TEXT, STRUCT, BINARY = (4.0, 5.7), (3.0, 6.6), (5.4, 7.3)
COMPRESSED, ENCRYPTED, PARTIAL = (7.5, 7.98), (7.78, 8.0), (6.0, 7.7)


class _W:
    """One window under construction."""

    def __init__(self, rng: np.random.Generator, ctx: dict):
        self.rng, self.ctx = rng, ctx
        self.events: list[dict] = []
        self.entropy: list[float] = []
        self.bytes = 0.0
        self.net = 0.0
        self.rate: float | None = None   # files/s of a hard-negative scenario (sets the event span); None = random span
        self.files = 0
        self.first = False   # the pod's first 20-64 events (no setup phase, no background noise): see START_BURSTS

    def ev(self, syscall: str, path: str, new_path: str | None = None, n: int = 1) -> None:
        # The live capture sees one open per file, not each read()/write(): n calls collapse to one open_r/open_w
        # (n=0 stays "no read"), explicit opens are implied by those.
        if syscall in OPEN_SYSCALLS:
            return
        if syscall in _READ_CALLS or syscall in _WRITE_CALLS:
            syscall, n = "open_r" if syscall in _READ_CALLS else "open_w", min(n, 1)
        for _ in range(n):
            self.events.append({"syscall": syscall, "path": path} | ({"new_path": new_path} if new_path else {}))

    def file(self, exts: list[str] | None = None, sub: str = "") -> str:
        r = self.rng
        ext = r.choice(exts or self.ctx["exts"])
        return f"{self.ctx['root']}{sub}/{r.choice(WORDS)}_{r.integers(1, 99999)}{ext}"

    def ent(self, rng_: tuple[float, float]) -> None:
        self.entropy.append(float(self.rng.uniform(*rng_)))

    def wrote(self, size_kb: tuple[float, float] = (1, 512)) -> None:
        self.bytes += self.rng.uniform(*size_kb) * 1024


# ── benign ───────────────────────────────────────────────────────────────────
def web_serve(w: _W, budget: int) -> None:
    log = f"{w.ctx['root']}/logs/access.log"
    while len(w.events) < budget:
        f = w.file()
        w.ev("openat", f)
        w.ev("read", f, n=int(w.rng.integers(1, 4)))
        w.ev("sendto", "", n=int(w.rng.integers(1, 3)))
        w.net += w.rng.uniform(1, 200) * 1024
        if w.rng.random() < 0.5:
            w.ev("write", log)
            w.wrote((0.1, 2))
            w.ent(TEXT)


def db_workload(w: _W, budget: int) -> None:
    files = [w.file([""], "/base/16384") for _ in range(int(w.rng.integers(2, 8)))]
    # Data files are opened O_RDWR: the capture emits one open_w per file per window, however many preads/pwrites follow.
    opened = set()
    while len(w.events) < budget:
        f = w.rng.choice(files)
        sc = w.rng.choice(["pread64", "pwrite64", "mmap", "pread64", "fsync"])
        if sc not in ("pread64", "pwrite64"):
            w.ev(sc, f)
        elif f not in opened:
            w.ev("pwrite64", f)
            opened.add(f)
        if sc == "pwrite64":
            w.wrote((8, 64))
            w.ent(STRUCT)


def backup_compress(w: _W, budget: int) -> None:
    """Archive files, or gzip logs in place (write .gz + unlink original): ransomware-like but benign."""
    gzip_logs = w.rng.random() < 0.4
    archive = w.file(ARCHIVE_EXT, "/backup")
    while len(w.events) < budget:
        src = w.file()
        w.ev("openat", src)
        w.ev("read", src, n=int(w.rng.integers(1, 6)))
        out = src + w.rng.choice([".gz", ".zst"]) if gzip_logs else archive
        w.ev("write", out, n=int(w.rng.integers(1, 4)))
        w.wrote((64, 8192))
        w.ent(COMPRESSED)
        if gzip_logs:
            w.ev("unlink", src)


def media_process(w: _W, budget: int) -> None:
    while len(w.events) < budget:
        src, out = w.file(MEDIA_EXT, "/incoming"), w.file(MEDIA_EXT, "/processed")
        w.ev("openat", src)
        w.ev("read", src, n=int(w.rng.integers(2, 8)))
        w.ev("mmap", src)
        w.ev("write", out, n=int(w.rng.integers(2, 8)))
        w.wrote((100, 5000))
        w.ent(COMPRESSED)
        if w.rng.random() < 0.3:
            w.ev("rename", out, out.rsplit(".", 1)[0] + w.rng.choice(MEDIA_EXT))


def log_rotate(w: _W, budget: int) -> None:
    base = f"{w.ctx['root']}/logs/{w.rng.choice(WORDS)}.log"
    while len(w.events) < budget:
        keep = int(w.rng.integers(3, 10))
        w.ev("unlink", f"{base}.{keep}")
        for i in range(keep - 1, 0, -1):
            w.ev("rename", f"{base}.{i}", f"{base}.{i + 1}")
        w.ev("rename", base, f"{base}.1")
        w.ev("openat", base)
        w.ev("write", base, n=int(w.rng.integers(1, 10)))
        w.wrote((1, 50))
        w.ent(TEXT)


def atomic_writes(w: _W, budget: int) -> None:
    while len(w.events) < budget:
        final = w.file()
        tmp = final + w.rng.choice([".tmp", ".part", ".swp", f".{w.rng.integers(100000, 999999)}", ".dpkg-new"])
        w.ev("openat", tmp)
        w.ev("write", tmp, n=int(w.rng.integers(1, 5)))
        w.ev("rename", tmp, final)
        w.wrote((0.5, 64))
        w.ent(w.rng.choice([TEXT, STRUCT, BINARY]))


def package_install(w: _W, budget: int) -> None:
    while len(w.events) < budget:
        if w.rng.random() < 0.2:
            w.ev("execve", w.rng.choice(["/usr/bin/pip", "/bin/sh", "/usr/bin/tar", "/usr/bin/gcc"]))
        f = w.file([".so", ".py", ".pyc", ".h", "", ".whl", ".tar.gz"], "/site-packages")
        w.ev("openat", f)
        w.ev("write", f, n=int(w.rng.integers(1, 4)))
        w.wrote((1, 2000))
        w.ent(COMPRESSED if f.endswith((".whl", ".gz")) else BINARY)
        if w.rng.random() < 0.3:
            w.ev("chmod", f)


def backup_upload(w: _W, budget: int) -> None:
    """Bulk read + network out, like exfiltration but to the backup target."""
    while len(w.events) < budget:
        f = w.file()
        w.ev("openat", f)
        w.ev("read", f, n=int(w.rng.integers(1, 6)))
        w.ev("sendto", "", n=int(w.rng.integers(1, 6)))
        w.net += w.rng.uniform(10, 4000) * 1024


def _mixed(w: _W, budget: int, actions: list) -> None:
    """Pick actions with per-window Dirichlet weights so ops scripts and recon overlap in their syscall mix."""
    p = w.rng.dirichlet(np.ones(len(actions)) * 0.7)
    while len(w.events) < budget:
        actions[w.rng.choice(len(actions), p=p)](w)


def _drop_binary(w: _W) -> None:
    dropped = f"/tmp/{w.rng.choice(['.', ''])}{w.rng.integers(1000, 99999)}{w.rng.choice(['', '.sh', '.bin'])}"
    w.ev("write", dropped)
    w.ev("chmod", dropped)
    w.wrote((5, 500))   # bytes count pod-wide; no entropy sample: /tmp is outside the scenario root, so no write is captured


def _connect(w: _W) -> None:
    w.ev("connect", "")
    w.net += w.rng.uniform(0.2, 20) * 1024      # health checks, beacons: small


def _walk(w: _W) -> None:
    f = w.file(sub=f"/{w.rng.choice(WORDS)}")
    w.ev("openat", f)
    if w.rng.random() < 0.3:
        w.ev("read", f)


OPS_TOOLS = ["/bin/sh", "/bin/bash", "/usr/bin/find", "/bin/cat", "/usr/bin/curl", "/bin/date", "/usr/bin/awk",
             "/bin/ls", "/usr/bin/id", "/bin/ps", "/bin/uname"]


def maintenance_script(w: _W, budget: int) -> None:
    """Cron/ops scripts: shells, find, curl health checks, cleanup unlinks, chmod — recon-like but benign."""
    _mixed(w, budget, [
        lambda w: w.ev("execve", w.rng.choice(OPS_TOOLS)),
        _walk,
        lambda w: w.ev("unlink", w.file([".tmp", ".old", ".bak", ".log"])),
        lambda w: w.ev("chmod", w.file()),
        _connect,
        _drop_binary,
        lambda w: (w.ev("openat", "/etc/passwd"), w.ev("read", "/etc/passwd")),
    ])


def encrypted_store(w: _W, budget: int) -> None:
    """Encrypted-at-rest stores (vault, restic, encrypted DB pages) rewrite files in place with ciphertext."""
    files = [w.file(["", ".db", ".dat", ".pack", ".idx"], "/store") for _ in range(int(w.rng.integers(2, 30)))]
    ro = w.rng.random() < 0.2   # stores open O_RDWR (one open_w live); a separate read-only open is the exception
    while len(w.events) < budget:
        f = w.rng.choice(files)
        w.ev("openat", f)
        if ro:
            w.ev(w.rng.choice(["read", "pread64"]), f)
        w.ev(w.rng.choice(["write", "pwrite64"]), f, n=int(w.rng.integers(1, 4)))
        w.wrote((4, 256))
        w.ent(ENCRYPTED)
        if w.rng.random() < 0.1:              # compaction: rewrite a whole segment
            w.ev("rename", f + ".compact", f)
            w.wrote((1024, 16384))


# ── hard-negative benign families (training-side only; lab rows cannot be recollected cheaply) ───────────────────
# Rename-heavy and high-entropy benign work that the lab covers only in part: the model must not learn "rename that
# changes the extension (or a high-entropy .gz next to a rename)" = ransomware. Rates 20-400 files/s.
CONTENT = [(TEXT, 0.45), (STRUCT, 0.25), (BINARY, 0.15), (COMPRESSED, 0.10), (ENCRYPTED, 0.05)]


def _rate(w: _W) -> None:
    w.rate = float(np.exp(w.rng.uniform(np.log(20), np.log(400))))


def _content(w: _W) -> tuple[float, float]:
    return CONTENT[w.rng.choice(len(CONTENT), p=[p for _, p in CONTENT])][0]


def _setup(w: _W, budget: int) -> None:
    """Half the windows start with plain low-entropy creates (the workload's setup phase) before the main loop."""
    if w.rng.random() < 0.5:
        for _ in range(int(budget * w.rng.uniform(0.1, 0.5))):
            w.ev("write", w.file())
            w.wrote()
            w.ent(TEXT)
            w.files += 1


def atomic_rename(w: _W, budget: int) -> None:
    """Atomic writes: temp file (.name.tmpNNN / name~) fsynced and renamed onto an existing name; editor saves."""
    _rate(w)
    _setup(w, budget)
    targets = [w.file() for _ in range(1 if w.rng.random() < 0.4 else int(w.rng.integers(2, 40)))]
    style = str(w.rng.choice(["dottmp", "tilde", "swp"]))
    while len(w.events) < budget:
        final = str(w.rng.choice(targets))
        d, name = final.rsplit("/", 1)
        content = _content(w)
        if style == "swp":        # editor save: .swp while editing, old content kept as name~, new content under the name
            w.ev("write", f"{d}/.{name}.swp")
            w.ev("rename", final, final + "~")
            w.ev("write", final)
            w.ev("unlink", f"{d}/.{name}.swp")
        else:
            tmp = f"{d}/.{name}.tmp{w.rng.integers(1000, 999999)}" if style == "dottmp" else final + "~"
            w.ev("write", tmp)
            w.ev("rename", tmp, final)
        w.wrote((0.5, 64))
        w.ent(content)
        w.files += 1


def logrotate_gz(w: _W, budget: int) -> None:
    """logrotate with compress: x.log → x.log.1, new x.log, then x.log.1.gz written (high entropy) and x.log.1 removed."""
    _rate(w)
    _setup(w, budget)
    logs = [f"{w.ctx['root']}/logs/{w.rng.choice(WORDS)}{i}.log" for i in range(int(w.rng.integers(1, 20)))]
    while len(w.events) < budget:
        base = str(w.rng.choice(logs))
        w.ev("rename", base, f"{base}.1")
        w.ev("write", base)
        w.ev("write", f"{base}.1.gz")
        w.ev("unlink", f"{base}.1")
        if w.rng.random() < 0.5:   # older generations are compressed too (rename keeps the .gz)
            w.ev("rename", f"{base}.1.gz", f"{base}.2.gz")
        w.wrote((10, 4096))
        w.ent(COMPRESSED)
        w.files += 1


def dpkg_install(w: _W, budget: int) -> None:
    """dpkg/rpm unpack: path.dpkg-new written next to each file, renamed over the old one, across many directories."""
    _rate(w)
    _setup(w, budget)
    dirs = [f"/usr/{w.rng.choice(['lib', 'share', 'bin'])}/{w.rng.choice(WORDS)}{i}" for i in range(int(w.rng.integers(3, 40)))]
    while len(w.events) < budget:
        final = w.file([".so", ".py", "", ".h", ".conf", ".mo", ".1.gz"], str(w.rng.choice(dirs)))
        w.ev("write", final + ".dpkg-new")
        if w.rng.random() < 0.4:
            w.ev("chmod", final + ".dpkg-new")
        w.ev("rename", final + ".dpkg-new", final)
        w.wrote((1, 3000))
        w.ent(COMPRESSED if final.endswith(".gz") else _content(w) if w.rng.random() < 0.3 else BINARY)
        w.files += 1


def git_npm(w: _W, budget: int) -> None:
    """git checkout (many plain writes, index.lock rename) or npm install (staged dir renames, tarballs)."""
    _rate(w)
    _setup(w, budget)
    npm = w.rng.random() < 0.5
    dirs = [f"/{w.rng.choice(WORDS)}{i}" for i in range(int(w.rng.integers(5, 60)))]
    while len(w.events) < budget:
        f = w.file([".js", ".json", ".py", ".md", ".ts", ""], str(w.rng.choice(dirs)))
        if npm and w.rng.random() < 0.3:
            pkg = f.rsplit("/", 1)[0]
            w.ev("write", pkg + ".tgz")
            w.ent(COMPRESSED)
            w.ev("rename", pkg + "-staging", pkg)
        w.ev("write", f)
        if not npm and w.rng.random() < 0.2:
            w.ev("unlink", f + ".orig")
        if w.rng.random() < 0.1:
            lock = f"{w.ctx['root']}/.git/index"
            w.ev("write", lock + ".lock")
            w.ev("rename", lock + ".lock", lock)
        w.wrote((0.5, 200))
        w.ent(_content(w) if w.rng.random() < 0.2 else TEXT if f.endswith((".js", ".py", ".md", ".ts", ".json")) else STRUCT)
        w.files += 1


def logrotate_start(w: _W, budget: int) -> None:
    """A logrotate/shell loop's start-up burst: write x.log (low entropy), rename x.log→x.log.1, gzip it into
    x.log.1.gz (entropy of a small .gz, 6.6-7.6); logs sit in 1-3 directories, gzip reads the rotated file."""
    _rate(w)
    w.rate = min(w.rate, float(np.exp(w.rng.uniform(np.log(5), np.log(150)))))
    if not w.first:
        _setup(w, budget)
    dirs = [f"{w.ctx['root']}{w.rng.choice(['', '/log', '/logs', '/var/log'])}" for _ in range(int(w.rng.integers(1, 4)))]
    logs = [f"{w.rng.choice(dirs)}/{w.rng.choice(WORDS)}{i}.log" for i in range(int(w.rng.integers(1, 12)))]
    while len(w.events) < budget:
        base = str(w.rng.choice(logs))
        w.ev("write", base)
        w.ent(TEXT)
        w.ev("rename", base, f"{base}.1")
        if w.rng.random() < 0.3:
            w.ev("read", f"{base}.1")
        w.ev("write", f"{base}.1.gz")
        w.ent((6.6, 7.6))
        if w.rng.random() < 0.3:
            w.ev("unlink", f"{base}.1")
        if w.rng.random() < 0.3:
            w.ev("rename", f"{base}.1.gz", f"{base}.2.gz")
        w.wrote((0.1, 4096))
        w.files += 1


def archive_burst(w: _W, budget: int) -> None:
    """tar/zip creation: read a few sources, write one high-entropy archive (sometimes via .tmp + rename)."""
    _rate(w)
    w.rate = min(w.rate, float(np.exp(w.rng.uniform(np.log(5), np.log(150)))))
    if not w.first:
        _setup(w, budget)
    while len(w.events) < budget:
        arc = w.file([".tar.gz", ".zip", ".tgz", ".tar.zst"], "/backup")
        for _ in range(int(w.rng.integers(0, 6))):
            w.ev("read", w.file())
        if w.rng.random() < 0.4:
            w.ev("write", arc + ".tmp")
            w.ev("rename", arc + ".tmp", arc)
        else:
            w.ev("write", arc)
        w.wrote((10, 8192))
        w.ent(COMPRESSED)
        w.files += 1


def _hex(w: _W, n: int = 64) -> str:
    return "".join(w.rng.choice(list("0123456789abcdef"), size=n))


def backup_repo(w: _W, budget: int) -> None:
    """Encrypting deduplicating backups (restic/borg/kopia style): originals are only read; encrypted, content-addressed
    pack files (repo/data/xx/<hash>, often temp + rename) are new; index/snapshot/lock files; prune reads old packs,
    writes repacked ones and unlinks the old; a local cache copies index files into another directory."""
    _rate(w)
    _setup(w, budget)
    repo = f"{w.ctx['root']}{w.rng.choice(['/repo', '/backup/repo', '/.restic', '/borg'])}"
    temp = str(w.rng.choice(["dot", "suffix", "none"]))
    srcs = [w.file(sub=f"/src{w.rng.integers(0, 9)}") for _ in range(int(w.rng.integers(5, 200)))]
    packs: list[str] = []

    def pack(sub: str = "data") -> str:
        h = _hex(w)
        final = f"{repo}/{sub}/{h[:2]}/{h}"
        tmp = {"dot": f"{repo}/{sub}/{h[:2]}/.{h}-tmp-{w.rng.integers(10**8)}", "suffix": final + ".tmp", "none": final}[temp]
        w.ev("write", tmp)
        if tmp != final:
            w.ev("rename", tmp, final)
        w.wrote((64, 16384))
        w.ent(ENCRYPTED if w.rng.random() < 0.8 else COMPRESSED)
        w.files += 1
        packs.append(final)
        return final

    w.ev("read", f"{repo}/config")
    lock = f"{repo}/locks/{_hex(w)}"
    w.ev("write", lock)
    prune = w.rng.random() < 0.3
    while len(w.events) < budget:
        if prune and packs and w.rng.random() < 0.4:      # repack: read an old pack, write a new one, drop the old
            old = packs.pop(int(w.rng.integers(len(packs))))
            w.ev("read", old)
            pack()
            w.ev("unlink", old)
            continue
        for _ in range(int(w.rng.integers(1, 12))):        # chunk a few originals into one pack
            w.ev("read", str(w.rng.choice(srcs)))
        pack()
        if w.rng.random() < 0.1:
            idx = pack("index")
            w.ev("read", idx)
            w.ev("write", f"{w.ctx['root']}/cache/{_hex(w, 16)}/index/{idx.rsplit('/', 1)[1]}")
            w.ent(ENCRYPTED)
    w.ev("write", f"{repo}/snapshots/{_hex(w)}")
    w.ent(ENCRYPTED)
    w.ev("unlink", lock)


def package_tree(w: _W, budget: int) -> None:
    """npm/yarn/pip install: read cached tarballs/wheels, many fresh files in a new tree, staged directory renames,
    cache writes via temp + rename (high-entropy .tgz/.whl), .pyc via temp + rename, the manifest rewritten."""
    _rate(w)
    _setup(w, budget)
    npm = w.rng.random() < 0.5
    tree = f"{w.ctx['root']}{'/app/node_modules' if npm else '/venv/lib/python3.13/site-packages'}"
    cache = f"{w.ctx['root']}{'/.npm/_cacache' if npm else '/.cache/pip'}"
    manifest = f"{w.ctx['root']}/app/{'package.json' if npm else 'requirements.txt'}"
    w.ev("read", manifest)
    while len(w.events) < budget:
        pkg = f"{w.rng.choice(WORDS)}{w.rng.integers(0, 999)}"
        h = _hex(w)
        blob = f"{cache}/{'content-v2/sha512' if npm else 'wheels'}/{h[:2]}/{h[2:4]}/{h}"
        if w.rng.random() < 0.5:                          # not cached yet: downloaded into the cache first
            tmp = f"{cache}/tmp/{_hex(w, 8)}"
            w.ev("write", tmp)
            w.ev("rename", tmp, blob)
            w.ent(COMPRESSED)
        w.ev("read", blob)
        dest = f"{tree}/.staging/{pkg}-{_hex(w, 8)}" if npm and w.rng.random() < 0.5 else f"{tree}/{pkg}"
        for _ in range(int(w.rng.integers(2, 25))):
            f = f"{dest}/{w.rng.choice(['lib/', 'src/', ''])}{w.rng.choice(WORDS)}{w.rng.choice(['.js', '.json', '.py', '.d.ts', '.md', '.so'])}"
            w.ev("write", f)
            w.ent(TEXT if not f.endswith(".so") else BINARY)
            w.files += 1
            if not npm and f.endswith(".py") and w.rng.random() < 0.5:
                pyc = f"{f.rsplit('/', 1)[0]}/__pycache__/{f.rsplit('/', 1)[1][:-3]}.cpython-313.pyc"
                tmp = f"{pyc}.{w.rng.integers(10**6)}"
                w.ev("write", tmp)
                w.ev("rename", tmp, pyc)
        if dest != f"{tree}/{pkg}":
            w.ev("rename", dest, f"{tree}/{pkg}")
        w.wrote((1, 2000))
        if w.rng.random() < 0.05:
            w.ev("chmod", f"{tree}/.bin/{pkg}")
    if w.rng.random() < 0.7:                               # npm rewrites its manifest and lock file
        w.ev("write", manifest)
        w.ev("write", manifest.replace("package.json", "package-lock.json"))
        w.ent(TEXT)


START_BURSTS = (logrotate_start, archive_burst)
HARD_NEGATIVES = (atomic_rename, logrotate_gz, dpkg_install, git_npm, backup_repo, package_tree) + START_BURSTS


# ── suspicious ───────────────────────────────────────────────────────────────
def recon(w: _W, budget: int) -> None:
    secrets = ["/etc/passwd", "/etc/shadow", "/proc/1/environ", "/var/run/secrets/kubernetes.io/serviceaccount/token",
               "/root/.ssh/id_rsa", "/proc/self/mountinfo"]
    _mixed(w, budget, [
        lambda w: w.ev("execve", w.rng.choice(OPS_TOOLS + ["/usr/bin/wget", "/usr/bin/nc", "/usr/bin/base64"])),
        lambda w: [w.ev(sc, f) for f in [str(w.rng.choice(secrets))] for sc in ("openat", "read")],
        _connect,
        _drop_binary,
        _walk,
    ])


def file_enumeration(w: _W, budget: int) -> None:
    while len(w.events) < budget:
        f = w.file(sub=f"/{w.rng.choice(WORDS)}")
        w.ev("openat", f)
        if w.rng.random() < 0.4:
            w.ev("read", f)


def permission_tamper(w: _W, budget: int) -> None:
    while len(w.events) < budget:
        f = w.file()
        w.ev(w.rng.choice(["chmod", "fchmodat", "chown"]), f)
        if w.rng.random() < 0.2:
            w.ev("execve", "/bin/sh")


# ── ransomware ───────────────────────────────────────────────────────────────
def _encrypt(w: _W, budget: int, mode: str, entropy: tuple[float, float], files: int | None = None) -> None:
    ext = w.ctx["ransom_ext"]
    originals: list[tuple[float, float]] = []
    done = 0
    while len(w.events) < budget and (files is None or done < files):
        src = w.file()
        w.ev("openat", src)
        w.ev("read", src, n=int(w.rng.integers(1, 5)))
        if w.rng.random() < 0.6:     # most tools reopen for writing (open r, read, close, open w, write)
            w.ev("openat", src)
        if mode == "inplace":
            if w.rng.random() < 0.3:
                w.ev("ftruncate", src)
            w.ev("write", src, n=int(w.rng.integers(1, 5)))
        elif mode == "rename":
            w.ev("write", src, n=int(w.rng.integers(1, 5)))
            w.ev("rename", src, src + ext if ext else src)
        else:  # copy then delete original
            w.ev("write", src + ext, n=int(w.rng.integers(1, 5)))
            w.ev("unlink", src)
        w.wrote((16, 8192))                   # whole documents rewritten
        w.ent(entropy)
        originals.append(TEXT if w.rng.random() < 0.5 else STRUCT)
        done += 1
    if w.ctx["note"] and w.rng.random() < 0.7:
        note = f"{w.ctx['root']}/{w.ctx['note']}"
        w.ev("write", note)
        w.ent(TEXT)
    # Samplers see some files before they are overwritten: low entropy early, high later.
    k = int(w.rng.integers(0, len(originals) + 1) * w.rng.random())
    for i, rng_ in enumerate(originals[:k]):
        w.entropy[i] = float(w.rng.uniform(*rng_))


def ransomware_rename(w: _W, budget: int) -> None:
    _encrypt(w, budget, "rename", ENCRYPTED)


def ransomware_inplace(w: _W, budget: int) -> None:
    _encrypt(w, budget, "inplace", ENCRYPTED)


def ransomware_copy_delete(w: _W, budget: int) -> None:
    _encrypt(w, budget, "copy", ENCRYPTED)


def ransomware_intermittent(w: _W, budget: int) -> None:
    _encrypt(w, budget, str(w.rng.choice(["inplace", "rename"])), PARTIAL)


def ransomware_slow(w: _W, budget: int) -> None:
    _encrypt(w, budget, str(w.rng.choice(["inplace", "rename", "copy"])), ENCRYPTED, files=int(w.rng.integers(1, 4)))


def ransomware_trickle(w: _W, budget: int) -> None:
    """1-5 files/s caught early: 2-12 files transformed after a setup/idle phase, so the first evidence is learned."""
    w.rate = float(w.rng.uniform(1, 5))
    w.files = int(w.rng.integers(2, 13))
    _encrypt(w, budget, str(w.rng.choice(["inplace", "rename", "rename", "copy"])),
             ENCRYPTED if w.rng.random() < 0.8 else PARTIAL, files=w.files)


HARD_POSITIVES = (ransomware_trickle,)   # used with --collected too: the lab's slow profiles are few


# ── exfiltration ─────────────────────────────────────────────────────────────
def exfiltration(w: _W, budget: int) -> None:
    stage = w.file(ARCHIVE_EXT, "/tmp") if w.rng.random() < 0.4 else None
    while len(w.events) < budget:
        f = w.file()
        w.ev("openat", f)
        w.ev("read", f, n=int(w.rng.integers(1, 6)))
        if stage:
            w.ev("write", stage)
            w.wrote()
            w.ent(COMPRESSED)
        w.ev(w.rng.choice(["sendto", "connect", "sendmsg"]), "", n=int(w.rng.integers(1, 6)))
        w.net += w.rng.uniform(50, 8000) * 1024


SCENARIOS = [  # (label, generator, weight)
    ("benign", web_serve, 1.0), ("benign", db_workload, 1.0), ("benign", backup_compress, 1.2),
    ("benign", media_process, 1.0), ("benign", log_rotate, 0.8), ("benign", atomic_writes, 1.0),
    ("benign", package_install, 0.8), ("benign", backup_upload, 0.8), ("benign", maintenance_script, 1.0),
    ("benign", encrypted_store, 0.8),
    ("benign", atomic_rename, 1.0), ("benign", logrotate_gz, 1.0), ("benign", dpkg_install, 1.0),
    ("benign", git_npm, 1.0), ("benign", backup_repo, 1.2), ("benign", package_tree, 1.2),
    ("benign", logrotate_start, 1.5), ("benign", archive_burst, 1.5),
    ("suspicious", recon, 1.0), ("suspicious", file_enumeration, 1.0), ("suspicious", permission_tamper, 0.6),
    ("ransomware", ransomware_rename, 0.8), ("ransomware", ransomware_inplace, 0.8),
    ("ransomware", ransomware_copy_delete, 0.6), ("ransomware", ransomware_intermittent, 0.7),
    ("ransomware", ransomware_slow, 0.7), ("ransomware", ransomware_trickle, 0.8),
    ("exfiltration", exfiltration, 1.8),
]
assert {label for label, _, _ in SCENARIOS} == set(SECURITY_LABELS)


def _window(rng: np.random.Generator, ctx: dict, gen, slow: bool) -> dict | None:
    w = _W(rng, ctx)
    total = int(rng.integers(10, 513))
    noise = rng.uniform(0.5, 0.8) if slow else rng.uniform(0.0, 0.6)
    if gen in START_BURSTS and rng.random() < 0.6:   # the pod's first window: only the burst itself
        w.first, total, noise = True, int(rng.integers(20, 65)), rng.uniform(0.0, 0.1)
    budget = max(1, int(total * (1 - noise)))
    if gen.__name__.startswith("ransomware") and rng.random() < 0.5:   # setup phase: low-entropy file creates, then the attack
        for _ in range(int(budget * rng.uniform(0.2, 0.7))):
            w.ev("write", w.file())
            w.wrote()
            w.ent(TEXT)
        budget += len(w.events)
    gen(w, budget)
    scenario = w.events
    w.events = []
    for _ in range(max(0, total - len(scenario))):
        w.ev(str(rng.choice(BACKGROUND)), str(rng.choice(BG_PATHS)))
    # Background noise lands at random times, but the scenario keeps its order (setup, then attack): the agent's
    # newest-64 recent_* features depend on it.
    is_scenario = rng.permutation([True] * len(scenario) + [False] * len(w.events))
    scen, bg = iter(scenario), iter(w.events)
    events = [next(scen) if s else next(bg) for s in is_scenario]
    root = ctx["root"] + "/"
    events = [e for e in events if e["syscall"] in CAPTURED and e["path"].startswith(root)][-MAX_WINDOW_EVENTS:]
    if not events:      # nothing the Falco rules would have emitted: the agent never sees this window
        return None
    # Event span; the agent also scores bursts early (BURST_EVENTS new events), so short spans occur too.
    span_s = float(rng.uniform(30, 60) if slow else rng.uniform(0.5, 60))
    if w.rate:   # hard negatives run at a stated files/s
        span_s = max(w.files * len(events) / max(len(scenario), 1), 1) / w.rate
    t0 = int(rng.integers(1_700_000_000_000, 1_800_000_000_000))
    for i, e in enumerate(events):
        e["ts_ms"] = t0 + int(i * span_s * 1000 / len(events))
    window_s = window_seconds(events[0]["ts_ms"], events[-1]["ts_ms"])   # the agent's definition, not a copy
    entropy = [] if rng.random() < 0.25 else w.entropy[-int(rng.integers(1, MAX_ENTROPY_SAMPLES + 1)):]
    # Pod-wide counters over the window: background (sidecars, app traffic, logs) + the scenario's bytes, writes
    # only partly flushed yet; a window's first evaluation (one sample) or an unreadable pid/cgroup gives None.
    first_eval = rng.random() < (0.6 if w.first else 0.15)   # a pod's first window has no earlier counter sample
    bg_write = 0.0 if rng.random() < 0.5 else rng.lognormal(np.log(1e3), 1.5) * window_s
    bg_net = rng.lognormal(np.log(2e3), 1.5) * window_s
    return {
        "events": events,
        "entropy": [min(8.0, max(0.0, x + rng.normal(0, 0.05))) for x in entropy],
        "window_s": window_s,
        "bytes_written": None if first_eval or rng.random() < 0.1 else bg_write + w.bytes * rng.uniform(0.0, 1.0) ** 0.5,
        "net_bytes_out": None if first_eval or rng.random() < 0.1 else bg_net + w.net,
    }


def generate(n_scenarios: int = 3000, seed: int = 0) -> list[dict]:
    """Records `{events, entropy, window_s, bytes_written, net_bytes_out, label, group, scenario}`."""
    rng = np.random.default_rng(seed)
    weights = np.asarray([wt for _, _, wt in SCENARIOS])
    records = []
    for i in range(n_scenarios):
        label, gen, _ = SCENARIOS[rng.choice(len(SCENARIOS), p=weights / weights.sum())]
        ctx = {
            "root": f"{rng.choice(ROOTS)}/{rng.choice(WORDS)}{rng.integers(0, 100)}",
            "exts": list(rng.choice(DOC_EXT, size=int(rng.integers(1, 6)))),
            "ransom_ext": (str(rng.choice(KNOWN_RANSOM_EXT)) if rng.random() < 0.4 else
                           "" if rng.random() < 0.3 else
                           "." + "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), size=int(rng.integers(3, 9))))),
            "note": str(rng.choice(NOTES)) if rng.random() < 0.5 else None,
        }
        for _ in range(int(rng.integers(1, 5))):
            rec = _window(rng, ctx, gen, slow=gen is ransomware_slow)
            if rec is not None:
                records.append(rec | {"label": label, "group": f"{seed}-{i}", "scenario": gen.__name__})
    return records
