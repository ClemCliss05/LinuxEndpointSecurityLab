
#ifndef FILE_OPEN_H
#define FILE_OPEN_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

struct file_key {
    __u32 dev_major;
    __u32 dev_minor;
    __u64 inode;
};

#endif

