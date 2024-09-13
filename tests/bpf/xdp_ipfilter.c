/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdio.h>
#include <bpf/bpf.h>
#include <endian.h>
#include <linux/if_link.h>

#include "xdp_ipfilter.skeleton.h"

#define IFINDEX 2

int main(void)
{
    struct xdp_ipfilter_bpf *obj;
    struct bpf_link *link;
    __u32 filtered_ip = htobe32(0xc0a80183);
    __u8 value = 1;
    int r;

    obj = xdp_ipfilter_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return -1;
    }

    r = xdp_ipfilter_bpf__load(obj);
    if (r) {
        fprintf(stderr, "failed to load BPF object\n");
        return -1;
    }

    r = bpf_map__update_elem(obj->maps.ip_map, &filtered_ip,
                             sizeof(filtered_ip), &value, sizeof(value),
                             BPF_ANY);
    if (r) {
        fprintf(stderr, "failed to insert value in the IPs map\n");
        goto end;
    }

    link = bpf_program__attach_xdp(obj->progs.xdp_prog, IFINDEX);
    if (!link) {
        fprintf(stderr, "failed to attach xdp_ipfilter.bpf.o to ifindex 2\n");
        return -1;
    }

    printf("Press any key to stop...\n");
    getchar();

    r = bpf_link__destroy(link);
    if (r)
        fprintf(stderr, "failed to destroy BPF link for xdp_ipfilter.bpf.o\n");
        
end:
    xdp_ipfilter_bpf__destroy(obj);

    return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
