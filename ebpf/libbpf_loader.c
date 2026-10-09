#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TASK_COMM_LEN 16

struct vista_ebpf_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tgid;
    uint32_t event_type;
    uint32_t spi;
    uint32_t bytes;
    char comm[TASK_COMM_LEN];
};

static volatile sig_atomic_t stop;
static uint64_t ring_events_seen;
static uint64_t malformed_ring_events;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop = 1;
}

static void json_string(const char *value)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\')
            printf("\\%c", *p);
        else if (*p >= 0x20)
            putchar(*p);
    }
    putchar('"');
}

static int handle_event(void *context, void *data, size_t size)
{
    const struct vista_ebpf_event *event = data;
    char comm[TASK_COMM_LEN + 1] = {0};
    const char *name;
    const char *function;
    char target[64];
    struct timespec realtime;
    struct tm tm_utc;
    char time_text[16];
    uint64_t timestamp_ns;

    (void)context;
    if (size < sizeof(*event)) {
        malformed_ring_events++;
        return 0;
    }
    ring_events_seen++;

    memcpy(comm, event->comm, TASK_COMM_LEN);
    switch (event->event_type) {
    case 1:
        name = "XFRM_OUT";
        function = "xfrm_output()";
        break;
    case 2:
        name = "XFRM_IN";
        function = "xfrm_input()";
        break;
    case 3:
        name = "SOCK_SEND";
        function = "sock_sendmsg()";
        break;
    default:
        name = "UNKNOWN";
        function = "unknown()";
        break;
    }

    if (clock_gettime(CLOCK_REALTIME, &realtime) != 0)
        return -errno;
    timestamp_ns = (uint64_t)realtime.tv_sec * 1000000000ULL + realtime.tv_nsec;
    gmtime_r(&realtime.tv_sec, &tm_utc);
    strftime(time_text, sizeof(time_text), "%H:%M:%S", &tm_utc);
    snprintf(target, sizeof(target), "PID %u (%s)", event->pid, comm);

    printf("{\"kind\":\"event\",\"id\":\"EBPF-%llu-%u\","
           "\"time\":\"%s\",\"timestamp_ns\":%llu,\"fn\":\"%s\","
           "\"eventType\":\"%s\",\"target\":",
           (unsigned long long)timestamp_ns, event->pid,
           time_text, (unsigned long long)timestamp_ns, function,
           name);
    json_string(target);
    printf(",\"pid\":%u,\"process_name\":", event->pid);
    json_string(comm);
    printf(",\"spi\":");
    if (event->spi)
        printf("\"0x%08x\"", event->spi);
    else
        printf("null");
    printf(",\"seq\":null,\"bytes\":");
    if (event->bytes)
        printf("%u", event->bytes);
    else
        printf("null");
    printf(",\"packets\":1,\"detail\":\"Observed kernel probe invocation\","
           "\"flag\":\"OBSERVED\",\"socket_id\":null,\"flow_id\":null}\n");
    fflush(stdout);
    return 0;
}

static void report_hook_hits(struct bpf_object *object)
{
    int map_fd = bpf_object__find_map_fd_by_name(object, "hook_hits");
    uint64_t values[5] = {0};

    if (map_fd < 0)
        return;
    for (__u32 key = 1; key <= 4; key++)
        bpf_map_lookup_elem(map_fd, &key, &values[key]);
    printf("{\"kind\":\"stats\",\"hookHits\":{\"XFRM_OUT\":%llu,"
           "\"XFRM_IN\":%llu,\"SOCK_SEND\":%llu},"
           "\"ringReserveFailures\":%llu,\"ringEventsSeen\":%llu,"
           "\"malformedRingEvents\":%llu}\n",
           (unsigned long long)values[1],
           (unsigned long long)values[2],
           (unsigned long long)values[3],
           (unsigned long long)values[4],
           (unsigned long long)ring_events_seen,
           (unsigned long long)malformed_ring_events);
    fflush(stdout);
}

static void report_status(const char *mode, const char *status, const char *error,
                          bool xfrm_out, bool xfrm_in, bool sock_send, bool udp_send,
                          bool sys_sendto)
{
    printf("{\"kind\":\"status\",\"mode\":\"%s\",\"status\":\"%s\","
           "\"error\":", mode, status);
    if (error)
        json_string(error);
    else
        printf("null");
    printf(",\"probes\":["
           "{\"name\":\"kprobe:xfrm_output\",\"target\":\"Linux XFRM outbound\",\"status\":\"%s\"},"
           "{\"name\":\"kprobe:xfrm_input\",\"target\":\"Linux XFRM inbound\",\"status\":\"%s\"},"
           "{\"name\":\"kprobe:sock_sendmsg\",\"target\":\"Socket transmission\",\"status\":\"%s\"},"
           "{\"name\":\"kprobe:udp_sendmsg\",\"target\":\"UDP transmission\",\"status\":\"%s\"},"
           "{\"name\":\"kprobe:__sys_sendto\",\"target\":\"Socket send syscall\",\"status\":\"%s\"}]}\n",
           xfrm_out ? "ATTACHED" : "UNAVAILABLE",
           xfrm_in ? "ATTACHED" : "UNAVAILABLE",
           sock_send ? "ATTACHED" : "UNAVAILABLE",
           udp_send ? "ATTACHED" : "UNAVAILABLE",
           sys_sendto ? "ATTACHED" : "UNAVAILABLE");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_link *links[5] = {0};
    struct ring_buffer *ring = NULL;
    const char *names[] = {
        "trace_xfrm_output",
        "trace_xfrm_input",
        "trace_sock_sendmsg",
        "trace_udp_sendmsg",
        "trace_sys_sendto",
    };
    bool attached[5] = {false};
    char error[512] = {0};
    int ring_map_fd;
    int result = EXIT_FAILURE;
    time_t last_stats = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s OBJECT\n", argv[0]);
        return EXIT_FAILURE;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    object = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(object)) {
        snprintf(error, sizeof(error), "open BPF object: %s",
                 strerror((int)-libbpf_get_error(object)));
        object = NULL;
        goto unavailable;
    }
    int load_result = bpf_object__load(object);
    if (load_result) {
        snprintf(error, sizeof(error), "load BPF object: %s",
                 strerror(load_result < 0 ? -load_result : errno));
        goto unavailable;
    }

    for (size_t i = 0; i < 5; i++) {
        program = bpf_object__find_program_by_name(object, names[i]);
        if (!program) {
            snprintf(error, sizeof(error), "missing BPF program %s", names[i]);
            goto unavailable;
        }
        links[i] = bpf_program__attach(program);
        if (libbpf_get_error(links[i])) {
            int link_error = (int)-libbpf_get_error(links[i]);
            links[i] = NULL;
            snprintf(error, sizeof(error), "attach %s: %s", names[i],
                     strerror(link_error));
            goto unavailable;
        }
        attached[i] = true;
    }

    ring_map_fd = bpf_object__find_map_fd_by_name(object, "events");
    if (ring_map_fd < 0) {
        snprintf(error, sizeof(error), "find ring buffer map: %s", strerror(errno));
        goto unavailable;
    }
    ring = ring_buffer__new(ring_map_fd, handle_event, NULL, NULL);
    if (!ring) {
        snprintf(error, sizeof(error), "create ring buffer: %s", strerror(errno));
        goto unavailable;
    }

    report_status("NATIVE_KERNEL_EBPF", "RUNNING", NULL,
                  attached[0], attached[1], attached[2], attached[3], attached[4]);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    while (!stop) {
        int poll_result = ring_buffer__poll(ring, 250);
        if (poll_result < 0 && poll_result != -EINTR) {
            fprintf(stderr, "ring buffer polling failed: %s\n", strerror(-poll_result));
            goto cleanup;
        }
        if (time(NULL) != last_stats) {
            last_stats = time(NULL);
            report_hook_hits(object);
        }
    }
    result = EXIT_SUCCESS;
    goto cleanup;

unavailable:
    report_status("UNAVAILABLE", "ERROR", error,
                  attached[0], attached[1], attached[2], attached[3], attached[4]);

cleanup:
    ring_buffer__free(ring);
    for (size_t i = 0; i < 5; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(object);
    return result;
}
