
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/fanotify.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EVENT_BUFFER_SIZE 4096

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

/*
 * Retrieve the effective UID of the process that triggered the event.
 *
 * The process is normally blocked while waiting for our permission
 * response, which gives us an opportunity to inspect /proc/<pid>/status.
 */
static int get_process_euid(pid_t pid, uid_t *euid)
{
    char path[64];
    char line[256];

    if (pid <= 0 || euid == NULL) {
        return -1;
    }

    int length = snprintf(path, sizeof(path),
                          "/proc/%ld/status", (long)pid);

    if (length < 0 || (size_t)length >= sizeof(path)) {
        return -1;
    }

    FILE *status = fopen(path, "r");

    if (status == NULL) {
        return -1;
    }

    int result = -1;

    while (fgets(line, sizeof(line), status) != NULL) {
        if (strncmp(line, "Uid:", 4) == 0) {
            unsigned int real_uid;
            unsigned int effective_uid;

            if (sscanf(line, "Uid:\t%u\t%u",
                       &real_uid, &effective_uid) == 2) {
                *euid = (uid_t)effective_uid;
                result = 0;
            }

            break;
        }
    }

    fclose(status);
    return result;
}

/*
 * Apply the access policy:
 * only the owner of the target file may open it.
 */
static bool evaluate_policy(int event_fd, pid_t pid)
{
    struct stat file_info;
    uid_t process_euid;

    if (fstat(event_fd, &file_info) == -1) {
        perror("fstat");
        return false;
    }

    if (get_process_euid(pid, &process_euid) == -1) {
        fprintf(stderr,
                "[POLICY] Cannot identify process UID. Denying access.\n");
        return false;
    }

    printf("[IDENTITY] PID=%ld | Process EUID=%u | File owner UID=%u\n",
           (long)pid,
           (unsigned int)process_euid,
           (unsigned int)file_info.st_uid);

    printf("[FILE] Device=%lu | Inode=%lu\n",
           (unsigned long)file_info.st_dev,
           (unsigned long)file_info.st_ino);

    return process_euid == file_info.st_uid;
}

/*
 * Send a permission decision to the kernel.
 */
static int send_permission_response(
    int fanotify_fd,
    int event_fd,
    uint32_t decision)
{
    struct fanotify_response response = {
        .fd = event_fd,
        .response = decision
    };

    ssize_t written;

    do {
        written = write(fanotify_fd, &response, sizeof(response));
    } while (written == -1 && errno == EINTR);

    if (written != (ssize_t)sizeof(response)) {
        if (written >= 0) {
            errno = EIO;
        }

        perror("fanotify permission response");
        return -1;
    }

    return 0;
}

/*
 * Read and process pending fanotify events.
 */
static int handle_events(int fanotify_fd)
{
    union {
        struct fanotify_event_metadata alignment;
        char buffer[EVENT_BUFFER_SIZE];
    } event_buffer;

    ssize_t length = read(fanotify_fd,
                          event_buffer.buffer,
                          sizeof(event_buffer.buffer));

    if (length == -1) {
        if (errno == EINTR) {
            return 0;
        }

        perror("read fanotify events");
        return -1;
    }

    if (length == 0) {
        fprintf(stderr, "Unexpected end of event stream.\n");
        return -1;
    }

    size_t remaining = (size_t)length;

    struct fanotify_event_metadata *metadata =
        (struct fanotify_event_metadata *)event_buffer.buffer;

    while (FAN_EVENT_OK(metadata, remaining)) {

        if (metadata->vers != FANOTIFY_METADATA_VERSION) {
            fprintf(stderr, "Unsupported metadata version.\n");
            return -1;
        }

        if (metadata->mask & FAN_Q_OVERFLOW) {
            fprintf(stderr, "[WARNING] Event queue overflow.\n");
        }

        if (metadata->fd >= 0) {

            if (metadata->mask & FAN_OPEN_PERM) {

                printf("\n[EVENT] FAN_OPEN_PERM | PID=%ld\n",
                       (long)metadata->pid);

                bool allowed = evaluate_policy(
                    metadata->fd,
                    metadata->pid
                );

                uint32_t decision = allowed ? FAN_ALLOW : FAN_DENY;

                printf("[POLICY] %s\n",
                       allowed ? "ALLOW" : "DENY");

                if (send_permission_response(
                        fanotify_fd,
                        metadata->fd,
                        decision) == -1) {
                    close(metadata->fd);
                    return -1;
                }
            }

            close(metadata->fd);
        }

        metadata = FAN_EVENT_NEXT(metadata, remaining);
    }

    if (remaining != 0) {
        fprintf(stderr,
                "[ERROR] Invalid or incomplete fanotify event data.\n");
        return -1;
    }

    return 0;
}

/*
 * Initialize fanotify and mark one specific file.
 */
static int initialize_fanotify(const char *target_path)
{
    int fanotify_fd = fanotify_init(
        FAN_CLASS_CONTENT | FAN_CLOEXEC,
        O_RDONLY | O_LARGEFILE
    );

    if (fanotify_fd == -1) {
        perror("fanotify_init");
        return -1;
    }

    if (fanotify_mark(
            fanotify_fd,
            FAN_MARK_ADD,
            FAN_OPEN_PERM,
            AT_FDCWD,
            target_path) == -1) {

        perror("fanotify_mark");
        close(fanotify_fd);
        return -1;
    }

    return fanotify_fd;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: sudo %s <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *target_path = realpath(argv[1], NULL);

    if (target_path == NULL) {
        perror("realpath");
        return EXIT_FAILURE;
    }

    struct sigaction action = {0};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, NULL) == -1 ||
        sigaction(SIGTERM, &action, NULL) == -1) {

        perror("sigaction");
        free(target_path);
        return EXIT_FAILURE;
    }

    printf("========================================\n");
    printf(" Linux Endpoint Security Lab - fanotify\n");
    printf("========================================\n");
    printf("Target: %s\n", target_path);
    printf("[INFO] Policy: only the file owner is allowed.\n");

    int fanotify_fd = initialize_fanotify(target_path);
    free(target_path);

    if (fanotify_fd == -1) {
        return EXIT_FAILURE;
    }

    printf("[INFO] fanotify initialized successfully.\n");
    printf("[INFO] Monitoring FAN_OPEN_PERM events.\n");
    printf("[INFO] Press Ctrl+C to stop.\n");

    while (!stop_requested) {
        if (handle_events(fanotify_fd) == -1) {
            close(fanotify_fd);
            return EXIT_FAILURE;
        }
    }

    printf("\n[INFO] Shutdown requested.\n");

    close(fanotify_fd);

    printf("[INFO] fanotify group closed.\n");
    printf("[INFO] Monitor stopped.\n");

    return EXIT_SUCCESS;
}
