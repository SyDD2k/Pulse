// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} disk_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CTR_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(enum counter_idx idx)
{
	__u32 key = idx;
	__u64 *val = bpf_map_lookup_elem(&counters, &key);

	if (val)
		*val += 1;
}

static __always_inline void emit_event(struct ebpfca_event *evt)
{
	bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}

static __always_inline __u64 now_ns(void)
{
	return bpf_ktime_get_ns();
}

SEC("tracepoint/sched/sched_process_fork")
int tp_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct ebpfca_event evt = {};

	evt.ts_ns = now_ns();
	evt.type = EVT_PROCESS_FORK;
	evt.pid = ctx->child_pid;
	evt.ppid = ctx->parent_pid;
	bpf_probe_read_kernel_str(evt.comm, sizeof(evt.comm),
				  ebpfca_data_loc(ctx, ctx->__data_loc_child_comm));
	emit_event(&evt);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct ebpfca_event evt = {};

	evt.ts_ns = now_ns();
	evt.type = EVT_PROCESS_EXEC;
	evt.pid = ctx->pid;
	bpf_get_current_comm(evt.comm, sizeof(evt.comm));
	emit_event(&evt);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
	struct ebpfca_event evt = {};

	evt.ts_ns = now_ns();
	evt.type = EVT_PROCESS_EXIT;
	evt.pid = ctx->pid;
	evt.value = ctx->prio;
	bpf_probe_read_kernel_str(evt.comm, sizeof(evt.comm), ctx->comm);
	emit_event(&evt);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	bump(CTR_SCHED_SWITCH);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int tp_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	bump(CTR_SCHED_WAKEUP);
	return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int tp_page_fault_user(struct trace_event_raw_exceptions *ctx)
{
	bump(CTR_PAGE_FAULT);
	return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int tp_page_fault_kernel(struct trace_event_raw_exceptions *ctx)
{
	bump(CTR_PAGE_FAULT);
	return 0;
}

SEC("tracepoint/block/block_rq_issue")
int tp_block_rq_issue(struct trace_event_raw_block_rq *ctx)
{
	struct ebpfca_event evt = {};
	__u64 key = ((__u64)ctx->dev << 32) | (__u32)ctx->sector;
	__u64 ts = now_ns();

	bpf_map_update_elem(&disk_start, &key, &ts, BPF_ANY);

	evt.ts_ns = ts;
	evt.type = EVT_DISK_ISSUE;
	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.value = ctx->bytes;
	evt.value2 = ctx->sector;
	bpf_get_current_comm(evt.comm, sizeof(evt.comm));
	bpf_probe_read_kernel_str(evt.detail, sizeof(evt.detail), ctx->rwbs);
	emit_event(&evt);
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int tp_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
{
	struct ebpfca_event evt = {};
	__u64 key = ((__u64)ctx->dev << 32) | (__u32)ctx->sector;
	__u64 *start_ts = bpf_map_lookup_elem(&disk_start, &key);
	__u64 end_ts = now_ns();
	__u64 latency = 0;

	if (start_ts)
		latency = end_ts - *start_ts;
	bpf_map_delete_elem(&disk_start, &key);

	evt.ts_ns = end_ts;
	evt.type = EVT_DISK_COMPLETE;
	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.value = latency;
	evt.value2 = ctx->nr_sector;
	bpf_get_current_comm(evt.comm, sizeof(evt.comm));
	bpf_probe_read_kernel_str(evt.detail, sizeof(evt.detail), ctx->rwbs);
	emit_event(&evt);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct ebpfca_event evt = {};

	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	evt.ts_ns = now_ns();
	evt.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(evt.comm, sizeof(evt.comm));
	evt.value = ctx->sport;
	evt.value2 = ctx->dport;

	if (ctx->newstate == TCP_ESTABLISHED && ctx->oldstate != TCP_ESTABLISHED) {
		evt.type = EVT_TCP_CONNECT;
		emit_event(&evt);
	} else if (ctx->newstate == TCP_CLOSE) {
		evt.type = EVT_TCP_CLOSE;
		emit_event(&evt);
	}
	return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tp_netif_receive_skb(void *ctx)
{
	bump(CTR_NET_RX);
	return 0;
}

SEC("tracepoint/net/net_dev_xmit")
int tp_net_dev_xmit(void *ctx)
{
	bump(CTR_NET_TX);
	return 0;
}
