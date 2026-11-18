#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "openat.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Temporary storage for openat syscalls currently in progress.
 *
 * Key   : Thread ID (TID)
 * Value : Information captured when entering openat
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct openat_event);
} inflight SEC(".maps");

/*
 * Per-CPU counters for monitoring internal failures.
 *
 * Each CPU has its own counter values, reducing contention.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/*
 * Ring buffer used to send completed syscall events
 * from kernel space to userspace.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");


/*
 * Increment one per-CPU statistic.
 */
static __always_inline void count_stat(__u32 index)
{
    __u64 *counter = bpf_map_lookup_elem(&stats, &index);

    if (counter)
        (*counter)++;
}


/*
 * Called when a thread enters the openat syscall.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct openat_event event = {};

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;

    event.uid = (__u32)uid_gid;
    event.gid = uid_gid >> 32;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /*
     * openat arguments:
     * args[0] = directory file descriptor
     * args[1] = pathname
     * args[2] = flags
     * args[3] = mode
     */
    const char *filename = (const char *)ctx->args[1];

    long result = bpf_probe_read_user_str(
        event.filename,
        sizeof(event.filename),
        filename
    );

    if (result < 0) {
        count_stat(STAT_PATH_READ_FAILURES);
        return 0;
    }

    /*
     * Store the event using the TID as its key.
     */
    __u32 tid = event.tid;

    if (bpf_map_update_elem(&inflight, &tid, &event, BPF_ANY) < 0)
        count_stat(STAT_INFLIGHT_UPDATE_FAILURES);

    return 0;
}


/*
 * Called when a thread exits the openat syscall.
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    /*
     * Retrieve the information saved at syscall entry.
     */
    struct openat_event *stored;

    stored = bpf_map_lookup_elem(&inflight, &tid);

    if (!stored)
        return 0;

    /*
     * Copy the map value onto the BPF stack before
     * deleting the map entry.
     */
    struct openat_event saved = *stored;

    if (bpf_map_delete_elem(&inflight, &tid) < 0)
        count_stat(STAT_INFLIGHT_DELETE_FAILURES);

    /*
     * Reserve space in the ring buffer.
     */
    struct openat_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (!event) {
        count_stat(STAT_RINGBUF_RESERVE_FAILURES);
        return 0;
    }

    /*
     * Add the syscall return value.
     */
    *event = saved;
    event->ret = ctx->ret;

    bpf_ringbuf_submit(event, 0);

    return 0;
}