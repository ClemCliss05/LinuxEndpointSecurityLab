#ifndef OPENAT_EVENT_H
#define OPENAT_EVENT_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

enum stat_index {
    STAT_PATH_READ_FAILURES,
    STAT_INFLIGHT_UPDATE_FAILURES,
    STAT_INFLIGHT_DELETE_FAILURES,
    STAT_RINGBUF_RESERVE_FAILURES,
    STAT_COUNT
};

struct openat_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;

    __s64 ret;

    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
};

#endif