#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#define BF_TIME_S 1000000000

struct bf_ratelimit
{
    __u64 current;
    __u64 last_time;
};

__u8 bf_ratelimit(void *map, __u64 key, __u64 limit)
{
    struct bf_ratelimit *ratelimit;
    __u64 current_time = bpf_ktime_get_ns() / BF_TIME_S;

    ratelimit = bpf_map_lookup_elem(map, &key);
    if (!ratelimit) {
        bpf_printk("failed to fetch the rule's ratelimit");
        return 1;
    }

    if (current_time != ratelimit->last_time)
        ratelimit->current = 0;

    ratelimit->current++;
    ratelimit->last_time = current_time;

    return (ratelimit->current > limit);
}
