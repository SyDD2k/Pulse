/* Minimal stub for local/CI compiles. On a real Fedora host generate:
 *   ./scripts/generate-vmlinux.sh
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef unsigned int u32;
typedef int pid_t;
typedef unsigned int dev_t;
typedef unsigned long sector_t;

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

enum {
	TCP_ESTABLISHED = 1,
	TCP_CLOSE = 7,
};

enum {
	IPPROTO_TCP = 6,
};

struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	u32 __data_loc_parent_comm;
	pid_t parent_pid;
	u32 __data_loc_child_comm;
	pid_t child_pid;
	char __data[0];
};

struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};

struct trace_event_raw_sched_process_exit {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};

struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
	char __data[0];
};

struct trace_event_raw_exceptions {
	struct trace_entry ent;
	long unsigned int address;
	long unsigned int ip;
	long unsigned int error_code;
	char __data[0];
};

struct trace_event_raw_block_rq {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	unsigned int bytes;
	short unsigned int ioprio;
	char rwbs[10];
	char comm[16];
	u32 __data_loc_cmd;
	char __data[0];
};

struct trace_event_raw_block_rq_completion {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	int error;
	short unsigned int ioprio;
	char rwbs[10];
	u32 __data_loc_cmd;
	char __data[0];
};

struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

#endif
