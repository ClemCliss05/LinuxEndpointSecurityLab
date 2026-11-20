
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "file_open.h"
#include "file_open.skel.h"

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int signal)
{
    (void)signal;
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct file_open_bpf *skel = NULL;
    struct stat file_info;
    struct file_key key = {0};
    __u8 value = 1;
    int error = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file-to-protect>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (stat(argv[1], &file_info) != 0) {
        perror("stat");
        return EXIT_FAILURE;
    }

    if (!S_ISREG(file_info.st_mode)) {
        fprintf(stderr, "Only regular files are supported.\n");
        return EXIT_FAILURE;
    }

    key.dev_major = major(file_info.st_dev);
    key.dev_minor = minor(file_info.st_dev);
    key.inode = file_info.st_ino;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = file_open_bpf__open();

    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return EXIT_FAILURE;
    }

    error = file_open_bpf__load(skel);

    if (error) {
        fprintf(stderr, "Failed to load BPF program: %d\n", error);
        goto cleanup;
    }

    if (bpf_map_update_elem(
            bpf_map__fd(skel->maps.protected_files),
            &key,
            &value,
            BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        error = -errno;
        goto cleanup;
    }

    error = file_open_bpf__attach(skel);

    if (error) {
        fprintf(stderr, "Failed to attach BPF LSM program: %d\n", error);
        goto cleanup;
    }

    printf("BPF LSM security agent active.\n");
    printf("Protected file: %s\n", argv[1]);
    printf("Device: %u:%u | Inode: %llu\n",
           key.dev_major,
           key.dev_minor,
           (unsigned long long)key.inode);
    printf("Press Ctrl+C to stop.\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    while (!exiting)
        pause();

cleanup:
    file_open_bpf__destroy(skel);

    printf("BPF LSM security agent stopped.\n");

    return error ? EXIT_FAILURE : EXIT_SUCCESS;
}
