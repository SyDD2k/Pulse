/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EBPFCA_COMMON_H
#define __EBPFCA_COMMON_H

#define TASK_COMM_LEN 16

enum event_type {
	EVT_PROCESS_FORK = 1,
	EVT_PROCESS_EXEC,
	EVT_PROCESS_EXIT,
	EVT_DISK_ISSUE,
	EVT_DISK_COMPLETE,
	EVT_TCP_CONNECT,
	EVT_TCP_CLOSE,
};

enum counter_idx {
	CTR_SCHED_SWITCH = 0,
	CTR_SCHED_WAKEUP,
	CTR_PAGE_FAULT,
	CTR_NET_RX,
	CTR_NET_TX,
	CTR_MAX,
};

struct ebpfca_event {
	__u64 ts_ns;
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 cpu;
	__u64 value;
	__u64 value2;
	char comm[TASK_COMM_LEN];
	char detail[32];
};

static __always_inline const void *ebpfca_data_loc(void *ctx, __u32 data_loc)
{
	return (const void *)((char *)ctx + (data_loc & 0xFFFF));
}

#endif
