#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

__u8 bf_ratelimit(struct bf_runtime *ctx)
{
    bpf_printk("Ratelimit got triggered");
    return 0;
}
