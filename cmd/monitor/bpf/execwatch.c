//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Layout confirmed directly against this kernel's own tracepoint format
// (`cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format`),
// not assumed from documentation -- this exact struct is what the kernel
// hands a program attached here, byte for byte.
struct sys_enter_execve_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tgid;
	__u64 cgroup_id;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct sys_enter_execve_args *ctx) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	e->timestamp_ns = bpf_ktime_get_ns();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->tgid = pid_tgid >> 32;
	e->pid = (__u32)pid_tgid;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
