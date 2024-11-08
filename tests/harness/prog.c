/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/prog.h"

#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/helper.h"
#include "core/logger.h"

struct bf_test_prog *bf_test_prog_get(const char *name)
{
    _free_bf_test_prog_ struct bf_test_prog *prog = NULL;
    int r;

    r = bf_test_prog_new(&prog);
    if (r < 0) {
        bf_err_r(r, "failed to create a new bf_test_prog");
        return NULL;
    }

    r = bf_test_prog_open(prog, name);
    if (r < 0) {
        bf_err_r(r, "failed to open the bf_test_prog's BPF program");
        return NULL;
    }

    return TAKE_PTR(prog);
}

int bf_test_prog_new(struct bf_test_prog **prog)
{
    bf_assert(prog);

    *prog = malloc(sizeof(struct bf_test_prog));
    if (!*prog)
        return bf_err_r(-ENOMEM, "failed to allocate a new bf_test_prog");

    (*prog)->fd = -1;

    return 0;
}

void bf_test_prog_free(struct bf_test_prog **prog)
{
    bf_assert(prog);

    if (!*prog)
        return;

    closep(&(*prog)->fd);
    freep((void *)prog);
}

int bf_test_prog_open(struct bf_test_prog *prog, const char *name)
{
    uint32_t id = 0;
    int r;

    while (true) {
        uint32_t len = sizeof(struct bpf_prog_info);
        struct bpf_prog_info info = {};
        _cleanup_close_ int prog_fd = -1;

        r = bpf_prog_get_next_id(id, &id);
        if (r < 0)
            return bf_err_r(r, "call to bpf_prog_get_next_id() failed");

        prog_fd = bpf_prog_get_fd_by_id(id);
        if (prog_fd < 0)
            return bf_err_r(prog_fd, "call to bpf_prog_get_fd_by_id() failed");

        r = bpf_obj_get_info_by_fd(prog_fd, &info, &len);
        if (r < 0)
            return bf_err_r(r, "call to bpf_obj_get_info_by_fd() failed");

        if (bf_streq(info.name, name)) {
            prog->fd = TAKE_FD(prog_fd);
            return 0;
        }
    }

    return -ENOENT;
}

int bf_test_prog_run(const struct bf_test_prog *prog, uint32_t expect,
                     void *pkt, size_t pkt_len)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt,
                .data_size_in = (uint32_t)pkt_len, .repeat = 1);
    int r;

    bf_assert(prog && pkt);

    r = bpf_prog_test_run_opts(prog->fd, &opts);
    if (r < 0)
        return bf_err_r(r, "failed to run the test program");

    if (opts.retval != expect) {
        bf_err("BPF_PROG_RUN returned %u, but %u expected", opts.retval,
               expect);
        return 1;
    }

    return 0;
}
