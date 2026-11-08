// KubeHeal file-activity sensor. lsm/ (or fexit/ fallback) programs on the LSM hooks the VFS calls once a lookup succeeded
// (security_file_open, security_path_{rename,unlink,truncate,chmod}, security_file_truncate), so only existing
// files, after the permission check, are seen. Filters in the kernel: pod cgroups (descendants of kubepods),
// excluded cgroups (namespace kubeheal), and the resolved path prefix; only hits reserve ring-buffer space.
// Paths are resolved like d_path(): dentry -> d_parent up to the mount root, then across mounts up to the
// task's fs->root, so they read as inside the container (/data/x), whatever the syscall argument was
// (relative, dirfd, /./, ..). No vmlinux.h: the few kernel structs are declared locally with CO-RE relocations.
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PLEN 256          // event path buffer; longer paths are dropped, never cut
#define DEPTH 64          // max path components + mount crossings
#define MAXPFX 4
#define PFXLEN 64
#define NSLOT 32          // walks per CPU: lsm programs run preemptible with no recursion guard, so claim atomically;
                          // every task preempted inside a hook holds one (8 ran out with 20 busy pods on 12 CPUs)
enum { K_OPEN, K_RENAME, K_UNLINK, K_TRUNCATE, K_FTRUNCATE, K_CHMOD };

#define PAI __attribute__((preserve_access_index))
struct qstr { __u32 len; const unsigned char *name; } PAI;
struct dentry { struct dentry *d_parent; struct qstr d_name; } PAI;
struct vfsmount { struct dentry *mnt_root; } PAI;
struct mount { struct mount *mnt_parent; struct dentry *mnt_mountpoint; struct vfsmount mnt; } PAI;
struct path { struct vfsmount *mnt; struct dentry *dentry; } PAI;
struct file { struct path f_path; unsigned int f_flags; } PAI;
struct fs_struct { struct path root; } PAI;
struct task_struct { struct fs_struct *fs; } PAI;
struct pt_regs___kh { long orig_ax; } PAI;   // x86_64: the syscall number

struct ev {
	__u64 ts, cgid;
	__u32 pid, nr, flags, kind;
	char path[PLEN];
	char new_path[PLEN];
};
struct pfx { __u32 len; char s[PFXLEN]; };
struct walk {
	__u32 busy;              // claimed from the per-CPU pool (take/give)
	__u64 d, vm, rd, rm;     // current dentry / vfsmount, the task's root dentry / vfsmount
	__s32 off, done;         // path = buf[off .. PLEN-1) (NUL at PLEN-1); done 1 = reached root, -1 = give up
	char buf[2 * PLEN];      // writes are masked to [0, PLEN) + len < PLEN: stays inside
};
struct wctx { struct walk *w; };

const volatile __u8 all_cgroups = 0;            // debug: every process, not only pods
const volatile struct pfx pfx[MAXPFX] = {};     // set before load: unused slots have len 0

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 24); } rb SEC(".maps");   // ~58k open records
struct { __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u32); } kubepods SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u64); __type(value, __u8); } skip SEC(".maps");
// lost events: [0] ring buffer full, [1] walk pool exhausted
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 2); __type(key, __u32); __type(value, __u64); } drops SEC(".maps");
struct pool { struct walk w[NSLOT]; };
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct pool); } scratch SEC(".maps");

static long step(__u64 i, struct wctx *c)
{
	struct walk *w = c->w;
	struct dentry *d = (void *)w->d;
	struct vfsmount *vm = (void *)w->vm;

	if (w->d == w->rd && w->vm == w->rm) {
		w->done = 1;
		return 1;
	}
	if (d == BPF_CORE_READ(vm, mnt_root)) {                          // mount root: continue at the mountpoint
		struct mount *m = (void *)vm - bpf_core_field_offset(struct mount, mnt);
		struct mount *mp = BPF_CORE_READ(m, mnt_parent);
		if (mp == m) {                                            // not reachable from the task root (internal mount)
			w->done = -1;
			return 1;
		}
		w->d = (__u64)BPF_CORE_READ(m, mnt_mountpoint);
		w->vm = (__u64)mp + bpf_core_field_offset(struct mount, mnt);
		return 0;
	}
	struct dentry *parent = BPF_CORE_READ(d, d_parent);
	__u32 len = BPF_CORE_READ(d, d_name.len);
	__s32 off = w->off;
	if (parent == d || len == 0 || len >= PLEN || off < (__s32)len + 1) {
		w->done = -1;
		return 1;
	}
	off -= len;
	bpf_probe_read_kernel(&w->buf[off & (PLEN - 1)], len & (PLEN - 1), BPF_CORE_READ(d, d_name.name));
	off--;
	w->buf[off & (PLEN - 1)] = '/';
	w->off = off;
	w->d = (__u64)parent;
	return 0;
}

static __always_inline void lost(__u32 k)
{
	__u64 *n = bpf_map_lookup_elem(&drops, &k);
	if (n)
		__sync_fetch_and_add(n, 1);
}

// Programs run with migration disabled, so the per-CPU pool stays this CPU's until give().
static __always_inline struct walk *take(void)
{
	__u32 k = 0;
	struct pool *p = bpf_map_lookup_elem(&scratch, &k);
	if (!p)
		return 0;
#pragma unroll
	for (int i = 0; i < NSLOT; i++)
		if (!__sync_lock_test_and_set(&p->w[i].busy, 1))
			return &p->w[i];
	lost(1);
	return 0;
}

static __always_inline void give(struct walk *w)
{
	*(volatile __u32 *)&w->busy = 0;      // contention is same-CPU only (preemption): a plain ordered store is enough
}

// 1 when the path resolved up to the task root; the path is then w->buf[w->off ..]
static __always_inline int resolve(struct walk *w, struct vfsmount *vm, struct dentry *d)
{
	struct task_struct *t = bpf_get_current_task_btf();
	w->rd = (__u64)BPF_CORE_READ(t, fs, root.dentry);
	w->rm = (__u64)BPF_CORE_READ(t, fs, root.mnt);
	w->d = (__u64)d;
	w->vm = (__u64)vm;
	w->off = PLEN - 1;
	w->done = 0;
	w->buf[PLEN - 1] = 0;
	struct wctx c = { .w = w };
	bpf_loop(DEPTH, step, &c, 0);
	if (w->done != 1)
		return 0;
	if (w->off == PLEN - 1) {                                         // the root itself
		w->off = PLEN - 2;
		w->buf[PLEN - 2] = '/';
	}
	return 1;
}

static __always_inline int match(struct walk *w)
{
	__s32 off = w->off;
#pragma unroll
	for (int i = 0; i < MAXPFX; i++) {
		__u32 n = pfx[i].len;
		if (!n || n > PFXLEN)
			continue;
		int ok = 1;
		for (int j = 0; j < PFXLEN; j++) {
			if (j >= n)
				break;
			if (w->buf[(off + j) & (2 * PLEN - 1)] != pfx[i].s[j]) {
				ok = 0;
				break;
			}
		}
		if (ok)
			return 1;
	}
	return 0;
}

static __always_inline int in_scope(void)
{
	if (!all_cgroups && bpf_current_task_under_cgroup(&kubepods, 0) != 1)
		return 0;
	__u64 cg = bpf_get_current_cgroup_id();
	return !bpf_map_lookup_elem(&skip, &cg);
}

static __always_inline __u32 syscall_nr(void)
{
	struct pt_regs___kh *r = (void *)bpf_task_pt_regs(bpf_get_current_task_btf());
	return BPF_CORE_READ(r, orig_ax);
}

static __always_inline void emit(__u32 kind, __u32 flags, struct walk *a, struct walk *b)
{
	// only renames carry new_path: other records stop before it (288 instead of 544 bytes)
	struct ev *e = b ? bpf_ringbuf_reserve(&rb, sizeof(*e), 0) : bpf_ringbuf_reserve(&rb, __builtin_offsetof(struct ev, new_path), 0);
	if (!e) {
		lost(0);
		return;
	}
	e->ts = bpf_ktime_get_boot_ns();
	e->cgid = bpf_get_current_cgroup_id();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->nr = syscall_nr();
	e->flags = flags;
	e->kind = kind;
	bpf_probe_read_kernel_str(e->path, PLEN, &a->buf[a->off & (PLEN - 1)]);
	if (b)
		bpf_probe_read_kernel_str(e->new_path, PLEN, &b->buf[b->off & (PLEN - 1)]);
	bpf_ringbuf_submit(e, 0);
}

static __always_inline void one(__u32 kind, __u32 flags, struct vfsmount *vm, struct dentry *d)
{
	struct walk *w = take();
	if (!w)
		return;
	if (resolve(w, vm, d) && match(w))
		emit(kind, flags, w, 0);
	give(w);
}

// Startup self-test: the sensor performs each operation itself; a hook that sees it records it and does nothing else.
// Userspace keeps, per hook, the lsm/ program if it fired (immune to inlining; needs `bpf` among the active LSMs),
// else the fexit/ one (the security_* function may be inlined away by LTO kernels: security_file_open on CachyOS 7.3).
enum { H_OPEN, H_RENAME, H_UNLINK, H_TRUNCATE, H_FTRUNCATE, H_CHMOD, H_N };
const volatile __u32 self_pid = 0;        // in the sensor's own pid namespace (dev/ino of /proc/self/ns/pid)
const volatile __u64 self_ns_dev = 0, self_ns_ino = 0;
__u8 testing = 0;                         // set by userspace during the self-test only
__u8 seen[2][H_N] = {};                   // [0] lsm, [1] fexit

static __always_inline int self(int via, int h)
{
	struct bpf_pidns_info ns;
	if (!testing || bpf_get_ns_current_pid_tgid(self_ns_dev, self_ns_ino, &ns, sizeof(ns)) || ns.tgid != self_pid)
		return 0;
	seen[via & 1][h % H_N] = 1;
	return 1;
}

static __always_inline void h_open(int via, struct file *f)
{
	if (!self(via, H_OPEN) && in_scope())
		one(K_OPEN, BPF_CORE_READ(f, f_flags), BPF_CORE_READ(f, f_path.mnt), BPF_CORE_READ(f, f_path.dentry));
}

static __always_inline void h_rename(int via, struct path *od, struct dentry *odn, struct path *nd, struct dentry *ndn)
{
	if (self(via, H_RENAME) || !in_scope())
		return;
	struct walk *a = take();
	if (!a)
		return;
	struct walk *b = take();
	if (b) {
		if (resolve(a, BPF_CORE_READ(od, mnt), odn) && resolve(b, BPF_CORE_READ(nd, mnt), ndn) && (match(a) || match(b)))
			emit(K_RENAME, 0, a, b);
		give(b);
	}
	give(a);
}

static __always_inline void h_unlink(int via, struct path *dir, struct dentry *dn)
{
	if (!self(via, H_UNLINK) && in_scope())
		one(K_UNLINK, 0, BPF_CORE_READ(dir, mnt), dn);
}

static __always_inline void h_truncate(int via, struct path *p)           // truncate(2)
{
	if (!self(via, H_TRUNCATE) && in_scope())
		one(K_TRUNCATE, 0, BPF_CORE_READ(p, mnt), BPF_CORE_READ(p, dentry));
}

static __always_inline void h_ftruncate(int via, struct file *f)  // ftruncate(2); also open(O_TRUNC), carried by the open event
{
	if (self(via, H_FTRUNCATE) || !in_scope())
		return;
	__u32 nr = syscall_nr();
	if (nr == 2 || nr == 257 || nr == 437 || nr == 85)        // open, openat, openat2, creat
		return;
	one(K_FTRUNCATE, 0, BPF_CORE_READ(f, f_path.mnt), BPF_CORE_READ(f, f_path.dentry));
}

static __always_inline void h_chmod(int via, struct path *p)              // chmod, fchmod, fchmodat, fchmodat2
{
	if (!self(via, H_CHMOD) && in_scope())
		one(K_CHMOD, 0, BPF_CORE_READ(p, mnt), BPF_CORE_READ(p, dentry));
}

// lsm/ programs never deny: they pass the previous verdict through and only observe allowed operations.
SEC("lsm/file_open")
int BPF_PROG(lsm_open, struct file *f, int ret) { if (!ret) h_open(0, f); return ret; }
SEC("fexit/security_file_open")
int BPF_PROG(fx_open, struct file *f, int ret) { if (!ret) h_open(1, f); return 0; }

SEC("lsm/path_rename")
int BPF_PROG(lsm_rename, struct path *od, struct dentry *odn, struct path *nd, struct dentry *ndn, unsigned int fl, int ret)
{ if (!ret) h_rename(0, od, odn, nd, ndn); return ret; }
SEC("fexit/security_path_rename")
int BPF_PROG(fx_rename, struct path *od, struct dentry *odn, struct path *nd, struct dentry *ndn, unsigned int fl, int ret)
{ if (!ret) h_rename(1, od, odn, nd, ndn); return 0; }

SEC("lsm/path_unlink")
int BPF_PROG(lsm_unlink, struct path *dir, struct dentry *dn, int ret) { if (!ret) h_unlink(0, dir, dn); return ret; }
SEC("fexit/security_path_unlink")
int BPF_PROG(fx_unlink, struct path *dir, struct dentry *dn, int ret) { if (!ret) h_unlink(1, dir, dn); return 0; }

SEC("lsm/path_truncate")
int BPF_PROG(lsm_truncate, struct path *p, int ret) { if (!ret) h_truncate(0, p); return ret; }
SEC("fexit/security_path_truncate")
int BPF_PROG(fx_truncate, struct path *p, int ret) { if (!ret) h_truncate(1, p); return 0; }

SEC("lsm/file_truncate")
int BPF_PROG(lsm_ftruncate, struct file *f, int ret) { if (!ret) h_ftruncate(0, f); return ret; }
SEC("fexit/security_file_truncate")
int BPF_PROG(fx_ftruncate, struct file *f, int ret) { if (!ret) h_ftruncate(1, f); return 0; }

SEC("lsm/path_chmod")
int BPF_PROG(lsm_chmod, struct path *p, unsigned short mode, int ret) { if (!ret) h_chmod(0, p); return ret; }
SEC("fexit/security_path_chmod")
int BPF_PROG(fx_chmod, struct path *p, unsigned short mode, int ret) { if (!ret) h_chmod(1, p); return 0; }

char LICENSE[] SEC("license") = "GPL";
