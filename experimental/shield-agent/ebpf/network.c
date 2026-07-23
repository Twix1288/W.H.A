// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Minimal structures to avoid vmlinux.h dependency for the smoke test
struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
};

// Tracepoint context format for sys_enter_connect
struct trace_event_raw_sys_enter_connect {
    unsigned long long unused;
    long syscall_nr;
    long fd;
    void *uservaddr;
    long addrlen;
};

struct network_event {
    unsigned int pid;
    unsigned int dst_ip;
    unsigned short dst_port;
    unsigned short padding;
};

// The Ring Buffer to send events to Go user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter_connect *ctx) {
    struct network_event *e;
    struct sockaddr_in sa = {};

    // Read sockaddr from user space
    if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0) {
        return 0;
    }

    // Only intercept IPv4 for now
    if (sa.sin_family != 2) { 
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->dst_ip = bpf_ntohl(sa.sin_addr); // Convert to host byte order for easier reading
    e->dst_port = bpf_ntohs(sa.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
