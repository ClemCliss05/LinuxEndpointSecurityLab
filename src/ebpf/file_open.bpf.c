
#include "vmlinux.h"
#include "file_open.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Files protected by the userspace security agent. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct file_key);
    __type(value, __u8);
} protected_files SEC(".maps");

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

SEC("lsm/file_open")
int BPF_PROG(enforce_file_policy, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    __u64 device = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    __u64 inode = BPF_CORE_READ(file, f_inode, i_ino);

    struct file_key key = {
        .dev_major = (__u32)(device >> MINORBITS),
        .dev_minor = (__u32)(device & MINORMASK),
        .inode = inode,
    };

    __u8 *protected = bpf_map_lookup_elem(&protected_files, &key);

    if (protected) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;

        char comm[16] = {};
        bpf_get_current_comm(comm, sizeof(comm));

        bpf_printk(
            "BPF LSM: DENIED PID=%d PROCESS=%s MAJOR=%u MINOR=%u INODE=%llu",
            pid,
            comm,
            key.dev_major,
            key.dev_minor,
            inode
        );

        return -13; /* -EACCES */
    }

    return 0;
}
