#include <uapi/linux/ptrace.h>

int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[495];
    bpf_usdt_readarg(2, ctx, &addr);
    bpf_probe_read(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("%s\\n", path);
    return 0;
};