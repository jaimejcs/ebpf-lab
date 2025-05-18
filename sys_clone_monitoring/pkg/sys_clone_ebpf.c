//go: build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_clone")
int handle_sys_clone(void *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_trace_printk("Hello, world | PID: %d\n", sizeof("Hello, world | PID: %d\n"), pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";