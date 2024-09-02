/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdio.h>

#include "xdp_printk.skeleton.h"

int main(void)
{
    struct xdp_printk_bpf *obj;
    int r;

    obj = xdp_printk_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "failed to open and load xdp_printk.bpf.o\n");
        return -1;
    }

    r = xdp_printk_bpf__attach(obj);
    if (r) {
        fprintf(stderr, "failed to attach xdp_printk.bpf.o\n");
        return -1;
    }

    printf("Press any key to stop...\n");
    getchar(); 

    xdp_printk_bpf__detach(obj);

    return 0;
}
