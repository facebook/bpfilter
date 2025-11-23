#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

__u8 bf_ratelimit(void)
{
    bpf_printk("Ratelimit got triggered");
    return 0;
}
