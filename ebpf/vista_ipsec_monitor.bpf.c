#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

enum vista_event_type {
    VISTA_EVENT_XFRM_OUT = 1,
    VISTA_EVENT_XFRM_IN = 2,
    VISTA_EVENT_SOCK_SEND = 3,
};

struct vista_ebpf_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 event_type;
    __u32 spi;
    __u32 bytes;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} hook_hits SEC(".maps");

static __always_inline int submit_event(__u32 event_type, __u32 spi, __u32 bytes)
{
    struct vista_ebpf_event *event;
    __u64 *hits;
    __u64 pid_tgid;

    hits = bpf_map_lookup_elem(&hook_hits, &event_type);
    if (hits)
        __sync_fetch_and_add(hits, 1);

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        __u32 drop_key = 4;
        __u64 *drops = bpf_map_lookup_elem(&hook_hits, &drop_key);
        if (drops)
            __sync_fetch_and_add(drops, 1);
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (__u32)pid_tgid;
    event->tgid = pid_tgid >> 32;
    event->event_type = event_type;
    event->spi = spi;
    event->bytes = bytes;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/xfrm_output")
int BPF_KPROBE(trace_xfrm_output)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    __u32 bytes = 0;

    if (skb)
        bytes = BPF_CORE_READ(skb, len);
    return submit_event(VISTA_EVENT_XFRM_OUT, 0, bytes);
}

SEC("kprobe/xfrm_input")
int BPF_KPROBE(trace_xfrm_input)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    __be32 network_spi = (__be32)PT_REGS_PARM3(ctx);
    __u32 bytes = 0;
    __u32 spi = bpf_ntohl(network_spi);

    if (skb)
        bytes = BPF_CORE_READ(skb, len);
    return submit_event(VISTA_EVENT_XFRM_IN, spi, bytes);
}

SEC("kprobe/sock_sendmsg")
int BPF_KPROBE(trace_sock_sendmsg)
{
    return submit_event(VISTA_EVENT_SOCK_SEND, 0, 0);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg)
{
    return submit_event(VISTA_EVENT_SOCK_SEND, 0, 0);
}

SEC("kprobe/__sys_sendto")
int BPF_KPROBE(trace_sys_sendto)
{
    return submit_event(VISTA_EVENT_SOCK_SEND, 0, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
