#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "openat.h"
#include "openat.skel.h"

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int signal)
{
    (void)signal;
    exiting = 1;
}


/*
 * Print one completed openat syscall event.
 */
static int handle_event(void *context, void *data, size_t data_size)
{
    (void)context;

    if (data_size != sizeof(struct openat_event)) {
        fprintf(stderr, "Invalid event size: %zu bytes\n", data_size);
        return 0;
    }

    const struct openat_event *event = data;

    if (event->ret >= 0) {
        printf(
            "SUCCESS PID=%-6u TID=%-6u PROCESS=%-16s FD=%lld FILE=%s\n",
            event->pid,
            event->tid,
            event->comm,
            (long long)event->ret,
            event->filename
        );
    } else {
        int error_number = (int)(-event->ret);

        printf(
            "FAILED  PID=%-6u TID=%-6u PROCESS=%-16s ERRNO=%d (%s) FILE=%s\n",
            event->pid,
            event->tid,
            event->comm,
            error_number,
            strerror(error_number),
            event->filename
        );
    }

    return 0;
}


/*
 * Read and aggregate per-CPU statistics.
 */
static int print_stats(struct openat_bpf *skel)
{
    int cpu_count = libbpf_num_possible_cpus();

    if (cpu_count < 0) {
        fprintf(stderr, "Failed to determine possible CPU count: %d\n",
                cpu_count);
        return cpu_count;
    }

    __u64 *values = calloc((size_t)cpu_count, sizeof(*values));

    if (!values) {
        perror("Failed to allocate statistics buffer");
        return -ENOMEM;
    }

    const char *names[STAT_COUNT] = {
        "Pathname read failures",
        "Inflight map update failures",
        "Inflight map delete failures",
        "Ring buffer reservation failures"
    };

    printf("\n--- eBPF statistics ---\n");
    printf("Possible CPUs: %d\n", cpu_count);

    int result = 0;

    for (__u32 key = 0; key < STAT_COUNT; key++) {
        memset(values, 0, (size_t)cpu_count * sizeof(*values));

        if (bpf_map_lookup_elem(
                bpf_map__fd(skel->maps.stats),
                &key,
                values) != 0) {
            perror("Failed to read statistics map");
            result = -errno;
            break;
        }

        __u64 total = 0;

        for (int cpu = 0; cpu < cpu_count; cpu++)
            total += values[cpu];

        printf("%-36s %llu\n", names[key],
               (unsigned long long)total);
    }

    free(values);

    return result;
}


int main(void)
{
    struct openat_bpf *skel = NULL;
    struct ring_buffer *ring_buffer = NULL;

    int error = 0;
    int loaded = 0;
    int attached = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Open the generated eBPF skeleton. */
    skel = openat_bpf__open();

    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return EXIT_FAILURE;
    }

    /* Load the eBPF program into the kernel. */
    error = openat_bpf__load(skel);

    if (error) {
        fprintf(stderr, "Failed to load BPF program: %d\n", error);
        goto cleanup;
    }

    loaded = 1;

    /* Attach the program to the openat tracepoints. */
    error = openat_bpf__attach(skel);

    if (error) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", error);
        goto cleanup;
    }

    attached = 1;

    /* Create the userspace consumer for the kernel ring buffer. */
    ring_buffer = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!ring_buffer) {
        fprintf(stderr, "Failed to create ring buffer\n");
        error = errno ? -errno : -ENOMEM;
        goto cleanup;
    }

    printf("Monitoring openat syscalls. Press Ctrl+C to stop.\n");

    while (!exiting) {
        int poll_result = ring_buffer__poll(ring_buffer, 250);

        if (poll_result == -EINTR)
            continue;

        if (poll_result < 0) {
            fprintf(stderr, "Ring buffer polling failed: %d\n",
                    poll_result);
            error = poll_result;
            break;
        }
    }

cleanup:
    /*
     * Stop receiving new events before reading final statistics.
     */
    if (attached)
        openat_bpf__detach(skel);

    ring_buffer__free(ring_buffer);

    if (loaded) {
        int stats_error = print_stats(skel);

        if (stats_error < 0 && error == 0)
            error = stats_error;
    }

    openat_bpf__destroy(skel);

    return error < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}