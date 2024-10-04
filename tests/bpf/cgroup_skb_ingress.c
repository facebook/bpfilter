/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpf/bpf.h>
#include <endian.h>
#include <linux/if_link.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "cgroup_skb_ingress.h"
#include "cgroup_skb_ingress.skeleton.h"

static volatile bool run = true;

void int_handler(int sig)
{
    run = false;
}

int main(int argc, char *argv[])
{
    struct cgroup_skb_ingress_bpf *obj;
    struct bpf_link *link;
    struct counters counters = {};
    __u32 key = 0;
    int cg_fd;
    const char *cg_path;
    int r;

    signal(SIGINT, int_handler);

    if (argc != 2) {
        fprintf(stderr, "usage: %s PATH_TO_CGROUP\n", argv[0]);
        return EXIT_FAILURE;
    }

    cg_path = argv[1];
    cg_fd = open(cg_path, O_DIRECTORY | O_RDONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "failed to open cgroup '%s'\n", cg_path);
        return EXIT_FAILURE;
    }

    obj = cgroup_skb_ingress_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        r = 1;
        goto end_close_cg;
    }

    r = bpf_map__update_elem(obj->maps.counters_map, &key,
                             sizeof(key), &counters, sizeof(counters),
                             BPF_ANY);
    if (r < 0) {
        fprintf(stderr, "failed to insert value in the IPs map\n");
        goto end_destroy_skel;
    }

    link = bpf_program__attach_cgroup(obj->progs.cgroup_skb_ingress, cg_fd);
    if (!link) {
        fprintf(stderr, "failed to attach cgroup_skb_ingress.bpf.o to cgroup '%s'\n",
                cg_path);
        r = 1;
        goto end_destroy_skel;
    }

    printf("Running cgroup_skb_ingress, press Ctrl+C to stop...\n");
    while (run) {
        r = bpf_map__lookup_elem(obj->maps.counters_map, &key, sizeof(key),
                                 &counters, sizeof(counters), 0);
        if (r < 0)
            continue;

        printf("\rpackets: %10llu, bytes: %10llu", counters.packets,
               counters.bytes);
        usleep(10000);
    }
    printf("\n");

    r = bpf_link__destroy(link);
    if (r < 0)
        fprintf(stderr, "failed to destroy BPF link for cgroup_skb_ingress.bpf.o\n");

end_destroy_skel:
    cgroup_skb_ingress_bpf__destroy(obj);
end_close_cg:
    close(cg_fd);

    return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
