#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define STR_MAX_SIZE 64

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[STR_MAX_SIZE]);
    __uint(max_entries, 1);
} str_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    const char str0[] = "Hello, world, from the stack";
    __u32 key = 0;
    char *str1;

    bpf_trace_printk(str0, sizeof(str0));

    str1 = bpf_map_lookup_elem(&str_map, &key);
    if (!str1)
        return XDP_PASS;

    bpf_trace_printk(str1, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

