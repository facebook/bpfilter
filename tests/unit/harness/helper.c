/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/helper.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "generator/codegen.h"
#include "generator/program.h"
#include "harness/cmocka.h"
#include "shared/helper.h"
#include "xlate/nft/nlmsg.h"
#include "xlate/nft/nlpart.h"

static const char *_readable_file_content = "Hello, world!";

char *bf_test_get_readable_tmp_filepath(void)
{
    int fd;
    size_t len = strlen(_readable_file_content);
    char tmppath[] = "/tmp/bpfltr_XXXXXX";
    char *path = NULL;

    fd = mkstemp(tmppath);
    if (fd < 0)
        fail_msg("HARNESS: failed to create a temporary file");

    if ((ssize_t)len != write(fd, _readable_file_content, len))
        fail_msg("HARNESS: failed to write to temporary file");

    close(fd);

    path = strdup(tmppath);
    if (!path)
        fail_msg("HARNESS: failed to write to temporary file");

    return path;
}

void bf_test_remove_tmp_file(char **path)
{
    if (!*path)
        return;

    if (unlink(*path) < 0)
        fail_msg("HARNESS: failed to remove '%s'", *path);

    free(*path);
    *path = NULL;
}

int bf_test_make_codegen(struct bf_codegen **codegen, enum bf_hook hook,
                         int nprogs)
{
    _cleanup_bf_codegen_ struct bf_codegen *c = NULL;
    int r;

    bf_assert(codegen);

    // So ifindex start a 1
    ++nprogs;

    r = bf_codegen_new(&c);
    if (r < 0)
        return r;

    for (int i = 1; i < nprogs; ++i) {
        _cleanup_bf_program_ struct bf_program *p = NULL;

        r = bf_program_new(&p, i, hook, BF_FRONT_IPT);
        if (r < 0)
            return r;

        r = bf_list_add_tail(&c->programs, p);
        if (r < 0)
            return r;

        TAKE_PTR(p);
    }

    *codegen = TAKE_PTR(c);

    return 0;
}

int bf_test_get_nlpart_add_chain(struct bf_nlpart **part)
{
    /* nftables' new chain message, in Netlink format. Generated using nftables:
     *   nft add chain ip bpfilter mychain \
     *       '{ type filter hook input priority 0; policy accept; }'
     */
    /* clang-format off */
    static const uint8_t raw[] = {
        // struct nlmsghdr
        0x58, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x01, 0x04,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // struct nfgenmsg
        0x02, 0x00, 0x00, 0x00,
        // Payload
            // Attr #1: NFTA_CHAIN_TABLE
            0x0d, 0x00, 0x01, 0x00,
            0x62, 0x70, 0x66, 0x69,
            0x6c, 0x74, 0x65, 0x72,
            0x00, 0x00, 0x00, 0x00,
            // Attr #2: NFTA_CHAIN_NAME
            0x0c, 0x00, 0x03, 0x00,
            0x6d, 0x79, 0x63, 0x68,
            0x61, 0x69, 0x6e, 0x00,
            // Attr #3: NFTA_CHAIN_POLICY
            0x08, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x00, 0x01,
            // Attr #4: NFTA_CHAIN_TYPE
            0x0b, 0x00, 0x07, 0x00,
            0x66, 0x69, 0x6c, 0x74,
            0x65, 0x72, 0x00, 0x00,
            // Attr #5 (nested): NFTA_CHAIN_HOOK
            0x14, 0x00, 0x04, 0x80,
                // Attr #5.1: NFTA_HOOK_HOOKNUM
                0x08, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x01,
                // Attr #5.2: NFTA_HOOK_PRIORITY
                0x08, 0x00, 0x02, 0x00,
                0x00, 0x00, 0x00, 0x00,
    };

    _cleanup_bf_nlpart_ struct bf_nlpart *_part = NULL;
    int r;

    r = bf_nlpart_new_from_nlmsghdr(&_part, (struct nlmsghdr *)raw);
    if (r < 0)
        return r;

    *part = TAKE_PTR(_part);

    return 0;
}

int bf_test_get_nlmsg_add_chain(struct bf_nlmsg **msg)
{
    /* clang-format on */

    _cleanup_bf_nlmsg_ struct bf_nlmsg *_msg = NULL;
    _cleanup_bf_nlpart_ struct bf_nlpart *part = NULL;
    int r;

    r = bf_test_get_nlpart_add_chain(&part);
    if (r < 0)
        return r;

    r = bf_nlmsg_new(&_msg);
    if (r < 0)
        return r;

    r = bf_nlmsg_add_part(_msg, part);
    if (r < 0)
        return r;

    TAKE_PTR(part);
    *msg = TAKE_PTR(_msg);

    return 0;
}
