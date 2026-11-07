// KubeHeal file-activity sensor: raw_syscalls/sys_enter -> filter in kernel -> ring buffer.
// x86_64 syscall numbers (the tracepoint ctx and syscall ABI are stable, so no vmlinux.h/CO-RE field relocations).
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PLEN 256
#define MAXPFX 4
#define PFXLEN 64
enum { G_OPEN_R, G_OPEN_W, G_RENAME, G_UNLINK, G_TRUNCATE, G_CHMOD, G_N };

struct ev {
	__u64 ts, cgid;
	__u32 pid, nr, flags, group;
	char path[PLEN];
	char new_path[PLEN];
};
struct pfx { __u32 len; char s[PFXLEN]; };
struct counts { __u64 n[G_N]; };
struct sys_enter_ctx { __u64 common; long id; unsigned long args[6]; };

const volatile __u8 all_cgroups = 0;   // debug: skip the cgroup filter

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } rb SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384); __type(key, __u64); __type(value, __u8); } cgroups SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, MAXPFX); __type(key, __u32); __type(value, struct pfx); } pfxs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384); __type(key, __u64); __type(value, struct counts); } counts SEC(".maps");

static __always_inline int match(const char *p)
{
#pragma unroll
	for (int i = 0; i < MAXPFX; i++) {
		__u32 k = i;
		struct pfx *x = bpf_map_lookup_elem(&pfxs, &k);
		if (!x || !x->len || x->len > PFXLEN)
			continue;
		int ok = 1;
		for (int j = 0; j < PFXLEN; j++) {
			if (j >= x->len)
				break;
			if (p[j] != x->s[j]) { ok = 0; break; }
		}
		if (ok)
			return 1;
	}
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int on_enter(struct sys_enter_ctx *c)
{
	const char *p1 = 0, *p2 = 0;
	__u32 flags = 0, grp = 0;
	unsigned long *a = c->args;

	switch (c->id) {
	case 2:   p1 = (void *)a[0]; flags = a[1]; grp = G_OPEN_R; break;                   // open
	case 257: p1 = (void *)a[1]; flags = a[2]; grp = G_OPEN_R; break;                   // openat
	case 437: {                                                                         // openat2
		__u64 f = 0;
		p1 = (void *)a[1]; grp = G_OPEN_R;
		bpf_probe_read_user(&f, sizeof(f), (void *)a[2]);
		flags = f;
		break;
	}
	case 85:  p1 = (void *)a[0]; flags = 0100 | 01 | 01000; grp = G_OPEN_R; break;      // creat = O_CREAT|O_WRONLY|O_TRUNC
	case 82:  p1 = (void *)a[0]; p2 = (void *)a[1]; grp = G_RENAME; break;              // rename
	case 264: case 316: p1 = (void *)a[1]; p2 = (void *)a[3]; grp = G_RENAME; break;    // renameat, renameat2
	case 87:  p1 = (void *)a[0]; grp = G_UNLINK; break;                                 // unlink
	case 263: p1 = (void *)a[1]; grp = G_UNLINK; break;                                 // unlinkat
	case 76:  p1 = (void *)a[0]; grp = G_TRUNCATE; break;                               // truncate
	case 90:  p1 = (void *)a[0]; grp = G_CHMOD; break;                                  // chmod
	case 268: case 452: p1 = (void *)a[1]; grp = G_CHMOD; break;                        // fchmodat, fchmodat2
	default: return 0;
	}
	if (grp == G_OPEN_R && (flags & 03 || flags & 01100))                               // same test as open_syscall()
		grp = G_OPEN_W;

	__u64 cg = bpf_get_current_cgroup_id();
	if (!all_cgroups && !bpf_map_lookup_elem(&cgroups, &cg))
		return 0;

	struct ev *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->path[0] = 0;
	e->new_path[0] = 0;
	bpf_probe_read_user_str(e->path, PLEN, p1);
	int hit = match(e->path);
	if (p2) {
		bpf_probe_read_user_str(e->new_path, PLEN, p2);
		hit |= match(e->new_path);
	}
	if (!hit) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->ts = bpf_ktime_get_boot_ns();
	e->cgid = cg;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->nr = c->id;
	e->flags = flags;
	e->group = grp;
	bpf_ringbuf_submit(e, 0);

	struct counts *cn = bpf_map_lookup_elem(&counts, &cg);
	if (!cn) {
		struct counts z = {};
		bpf_map_update_elem(&counts, &cg, &z, BPF_NOEXIST);
		cn = bpf_map_lookup_elem(&counts, &cg);
	}
	if (cn && grp < G_N)
		__sync_fetch_and_add(&cn->n[grp], 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
