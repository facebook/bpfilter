/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/helper.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/xlate/nft/nfgroup.h"
#include "core/chain.h"
#include "core/helper.h"
#include "core/rule.h"
#include "harness/cmocka.h"

struct nlmsghdr;

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

struct bf_chain *bf_test_chain(enum bf_hook hook, enum bf_verdict policy)
{
    struct bf_chain *chain;

    assert_int_equal(0, bf_chain_new(&chain, hook, policy, NULL, NULL));
    
    return chain;
}

struct bf_cgen *bf_test_cgen(enum bf_front front, enum bf_hook hook,
                             enum bf_verdict verdict, size_t nprogs)
{
    struct bf_cgen *cgen;
    struct bf_chain *chain = bf_test_chain(hook, verdict);

    assert_int_equal(0, bf_cgen_new(&cgen, front, &chain));

    for (size_t i = 0; i < nprogs; ++i) {
        struct bf_program *program;

        // ifindex should start at 1.
        assert_int_equal(0, bf_program_new(&program, i + 1, hook, front, cgen->chain));
        assert_int_equal(0, bf_list_add_tail(&cgen->programs, program));
    }

    return cgen;
}

struct nlmsghdr *bf_test_get_nlmsghdr(size_t nmsg, size_t *len)
{
    // clang-format off
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
    // clang-format on

    size_t msg_size = ARRAY_SIZE(raw) * nmsg;
    _cleanup_free_ void *msg = NULL;

    msg = malloc(msg_size);
    if (!msg)
        return NULL;

    for (size_t i = 0; i < nmsg; ++i)
        memcpy(msg + i * ARRAY_SIZE(raw), raw, ARRAY_SIZE(raw));

    *len = msg_size;

    return (struct nlmsghdr *)TAKE_PTR(msg);
}

struct bf_nfgroup *bf_test_get_nfgroup(size_t nmsg, size_t *len)
{
    _cleanup_bf_nfgroup_ struct bf_nfgroup *group = NULL;
    _cleanup_free_ struct nlmsghdr *nlh = NULL;

    nlh = bf_test_get_nlmsghdr(nmsg, len);
    assert_non_null(nlh);

    assert_int_equal(bf_nfgroup_new_from_stream(&group, nlh, *len), 0);

    return TAKE_PTR(group);
}

struct bf_rule *bf_test_get_rule(void)
{
    _cleanup_bf_rule_ struct bf_rule *rule = NULL;

    assert_int_equal(0, bf_rule_new(&rule));

    rule->index = 1;
    rule->ifindex = 2;

    for (int i = 0; i < 10; ++i)
        assert_int_equal(
            0, bf_rule_add_matcher(rule, 0, 0, (void *)&i, sizeof(i)));

    rule->counters = true;
    rule->verdict = 1;

    return TAKE_PTR(rule);
}
