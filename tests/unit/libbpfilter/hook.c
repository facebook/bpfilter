/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/hook.h>

#include <sys/socket.h>

#include "bpfilter/dump.h"
#include "bpfilter/list.h"
#include "bpfilter/pack.h"
#include "fake.h"
#include "test.h"

static void hook_to_str(void **state)
{
    (void)state;

    // Test all valid hooks
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook) {
        const char *str = bf_hook_to_str(hook);
        assert_non_null(str);
    }

    // Verify specific hook names
    assert_string_equal(bf_hook_to_str(BF_HOOK_XDP), "BF_HOOK_XDP");
    assert_string_equal(bf_hook_to_str(BF_HOOK_TC_INGRESS),
                        "BF_HOOK_TC_INGRESS");
    assert_string_equal(bf_hook_to_str(BF_HOOK_NF_PRE_ROUTING),
                        "BF_HOOK_NF_PRE_ROUTING");
}

static void hook_from_str(void **state)
{
    (void)state;

    // Test valid conversions
    assert_int_equal(bf_hook_from_str("BF_HOOK_XDP"), BF_HOOK_XDP);
    assert_int_equal(bf_hook_from_str("BF_HOOK_TC_INGRESS"),
                     BF_HOOK_TC_INGRESS);
    assert_int_equal(bf_hook_from_str("BF_HOOK_NF_PRE_ROUTING"),
                     BF_HOOK_NF_PRE_ROUTING);
    assert_int_equal(bf_hook_from_str("BF_HOOK_TC_EGRESS"), BF_HOOK_TC_EGRESS);

    // Test round-trip for all hooks
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook) {
        const char *str = bf_hook_to_str(hook);
        assert_int_equal(bf_hook_from_str(str), hook);
    }

    // Test invalid strings
    assert_err((int)bf_hook_from_str("BF_HOOK_XD"));
    assert_err((int)bf_hook_from_str("invalid"));
    assert_err((int)bf_hook_from_str("BF_HOOK"));
}

static void hook_to_flavor(void **state)
{
    (void)state;

    // Test all hooks return valid flavors
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook) {
        enum bf_flavor flavor = bf_hook_to_flavor(hook);
        assert_int_gte(flavor, 0);
        assert_int_lt(flavor, _BF_FLAVOR_MAX);
    }

    // Verify specific conversions
    assert_int_equal(bf_hook_to_flavor(BF_HOOK_XDP), BF_FLAVOR_XDP);
    assert_int_equal(bf_hook_to_flavor(BF_HOOK_TC_INGRESS), BF_FLAVOR_TC);
    assert_int_equal(bf_hook_to_flavor(BF_HOOK_TC_EGRESS), BF_FLAVOR_TC);
    assert_int_equal(bf_hook_to_flavor(BF_HOOK_NF_PRE_ROUTING), BF_FLAVOR_NF);
    assert_int_equal(bf_hook_to_flavor(BF_HOOK_NF_LOCAL_IN), BF_FLAVOR_NF);
    assert_int_equal(bf_hook_to_flavor(BF_HOOK_CGROUP_INGRESS),
                     BF_FLAVOR_CGROUP);
    assert_int_equal(bf_hook_to_flavor(BF_HOOK_CGROUP_EGRESS),
                     BF_FLAVOR_CGROUP);
}

static void hook_to_bpf_attach_type(void **state)
{
    (void)state;

    // Test all hooks return valid attach types
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook) {
        enum bf_bpf_attach_type attach_type = bf_hook_to_bpf_attach_type(hook);
        assert_int_gte(attach_type, 0);
    }

    // Verify specific conversions
    assert_int_equal(bf_hook_to_bpf_attach_type(BF_HOOK_XDP), BF_BPF_XDP);
    assert_int_equal(bf_hook_to_bpf_attach_type(BF_HOOK_TC_INGRESS),
                     BF_BPF_TCX_INGRESS);
    assert_int_equal(bf_hook_to_bpf_attach_type(BF_HOOK_TC_EGRESS),
                     BF_BPF_TCX_ENGRESS);
}

static void hook_to_bpf_prog_type(void **state)
{
    (void)state;

    // Test all hooks return valid prog types
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook) {
        enum bf_bpf_prog_type prog_type = bf_hook_to_bpf_prog_type(hook);
        assert_int_gte(prog_type, 0);
    }

    // Verify specific conversions
    assert_int_equal(bf_hook_to_bpf_prog_type(BF_HOOK_XDP),
                     BF_BPF_PROG_TYPE_XDP);
    assert_int_equal(bf_hook_to_bpf_prog_type(BF_HOOK_TC_INGRESS),
                     BF_BPF_PROG_TYPE_SCHED_CLS);
    assert_int_equal(bf_hook_to_bpf_prog_type(BF_HOOK_NF_PRE_ROUTING),
                     BF_BPF_PROG_TYPE_NETFILTER);
}

static void hook_to_nf_hook(void **state)
{
    (void)state;

    // Test valid NF hook conversions
    assert_int_equal(bf_hook_to_nf_hook(BF_HOOK_NF_PRE_ROUTING),
                     BF_NF_INET_PRE_ROUTING);
    assert_int_equal(bf_hook_to_nf_hook(BF_HOOK_NF_LOCAL_IN),
                     BF_NF_INET_LOCAL_IN);
    assert_int_equal(bf_hook_to_nf_hook(BF_HOOK_NF_FORWARD),
                     BF_NF_INET_FORWARD);
    assert_int_equal(bf_hook_to_nf_hook(BF_HOOK_NF_LOCAL_OUT),
                     BF_NF_INET_LOCAL_OUT);
    assert_int_equal(bf_hook_to_nf_hook(BF_HOOK_NF_POST_ROUTING),
                     BF_NF_INET_POST_ROUTING);

    // Test invalid NF hook conversions (non-NF hooks)
    assert_err((int)bf_hook_to_nf_hook(BF_HOOK_XDP));
    assert_err((int)bf_hook_to_nf_hook(BF_HOOK_TC_INGRESS));
    assert_err((int)bf_hook_to_nf_hook(BF_HOOK_CGROUP_INGRESS));
}

static void hook_from_nf_hook(void **state)
{
    (void)state;

    // Test valid conversions
    assert_int_equal(bf_hook_from_nf_hook(BF_NF_INET_PRE_ROUTING),
                     BF_HOOK_NF_PRE_ROUTING);
    assert_int_equal(bf_hook_from_nf_hook(BF_NF_INET_LOCAL_IN),
                     BF_HOOK_NF_LOCAL_IN);
    assert_int_equal(bf_hook_from_nf_hook(BF_NF_INET_FORWARD),
                     BF_HOOK_NF_FORWARD);
    assert_int_equal(bf_hook_from_nf_hook(BF_NF_INET_LOCAL_OUT),
                     BF_HOOK_NF_LOCAL_OUT);
    assert_int_equal(bf_hook_from_nf_hook(BF_NF_INET_POST_ROUTING),
                     BF_HOOK_NF_POST_ROUTING);

    // Test round-trip for all NF hooks
    for (enum bf_nf_inet_hooks nf_hook = 0; nf_hook < BF_NF_INET_NUMHOOKS;
         ++nf_hook) {
        enum bf_hook hook = bf_hook_from_nf_hook(nf_hook);
        assert_int_equal(bf_hook_to_nf_hook(hook), nf_hook);
    }

    // Test invalid conversions
    assert_err((int)bf_hook_from_nf_hook(-1));
    assert_err((int)bf_hook_from_nf_hook(BF_NF_INET_NUMHOOKS + 1));
}

static void nf_hook_to_str(void **state)
{
    (void)state;

    // Test all valid NF hooks
    assert_non_null(bf_nf_hook_to_str(BF_NF_INET_PRE_ROUTING));
    assert_non_null(bf_nf_hook_to_str(BF_NF_INET_LOCAL_IN));
    assert_non_null(bf_nf_hook_to_str(BF_NF_INET_FORWARD));
    assert_non_null(bf_nf_hook_to_str(BF_NF_INET_LOCAL_OUT));
    assert_non_null(bf_nf_hook_to_str(BF_NF_INET_POST_ROUTING));

    // Verify specific strings
    assert_string_equal(bf_nf_hook_to_str(BF_NF_INET_PRE_ROUTING),
                        "nf_prerouting");
    assert_string_equal(bf_nf_hook_to_str(BF_NF_INET_LOCAL_IN), "nf_input");
    assert_string_equal(bf_nf_hook_to_str(BF_NF_INET_FORWARD), "nf_forward");
    assert_string_equal(bf_nf_hook_to_str(BF_NF_INET_LOCAL_OUT), "nf_output");
    assert_string_equal(bf_nf_hook_to_str(BF_NF_INET_POST_ROUTING),
                        "nf_postrouting");

    // Test invalid hook
    assert_null(bf_nf_hook_to_str(-1));
    assert_null(bf_nf_hook_to_str(BF_NF_INET_NUMHOOKS + 1));
}

static void hookopts_new_and_free(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;

    (void)state;

    // Test allocation
    assert_ok(bf_hookopts_new(&hookopts));
    assert_non_null(hookopts);
    assert_int_equal(hookopts->used_opts, 0);

    // Test free (cleanup attribute will handle this)
}

static void hookopts_parse_ifindex(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt1[] = "ifindex=42";
    char opt2[] = "ifindex=100";

    (void)state;

    assert_ok(bf_hookopts_new(&hookopts));

    // Test valid ifindex
    assert_ok(bf_hookopts_parse_opt(hookopts, opt1));
    assert_int_equal(hookopts->ifindex, 42);
    assert_true(bf_hookopts_is_used(hookopts, BF_HOOKOPTS_IFINDEX));

    // Test another value (overwrite)
    assert_ok(bf_hookopts_parse_opt(hookopts, opt2));
    assert_int_equal(hookopts->ifindex, 100);
}

static void hookopts_parse_cgpath(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt[] = "cgpath=/sys/fs/cgroup";

    (void)state;

    assert_ok(bf_hookopts_new(&hookopts));

    // Test valid cgpath
    assert_ok(bf_hookopts_parse_opt(hookopts, opt));
    assert_non_null(hookopts->cgpath);
    assert_string_equal(hookopts->cgpath, "/sys/fs/cgroup");
    assert_true(bf_hookopts_is_used(hookopts, BF_HOOKOPTS_CGPATH));
}

static void hookopts_parse_family(void **state)
{
    char opt1[] = "family=inet4";
    char opt2[] = "family=inet6";
    char opt3[] = "family=inet";
    char opt4[] = "family=invalid";

    (void)state;

    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        assert_ok(bf_hookopts_new(&hookopts));

        // Test inet4 - family is deprecated, so it's accepted but not set
        assert_ok(bf_hookopts_parse_opt(hookopts, opt1));
    }

    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        assert_ok(bf_hookopts_new(&hookopts));

        // Test inet6 - family is deprecated, so it's accepted but not set
        assert_ok(bf_hookopts_parse_opt(hookopts, opt2));
    }

    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        assert_ok(bf_hookopts_new(&hookopts));

        // Test invalid family
        assert_err(bf_hookopts_parse_opt(hookopts, opt3));
        assert_err(bf_hookopts_parse_opt(hookopts, opt4));
    }
}

static void hookopts_parse_priorities(void **state)
{
    (void)state;

    // Test valid priorities
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt[] = "priorities=100-200";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt));
        assert_int_equal(hookopts->priorities[0], 100);
        assert_int_equal(hookopts->priorities[1], 200);
        assert_true(bf_hookopts_is_used(hookopts, BF_HOOKOPTS_PRIORITIES));
    }

    // Test reverse order
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt[] = "priorities=200-100";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt));
        assert_int_equal(hookopts->priorities[0], 200);
        assert_int_equal(hookopts->priorities[1], 100);
    }

    // Test invalid formats
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt1[] = "priorities=100";
        char opt2[] = "priorities=100-";
        char opt3[] = "priorities=-100";
        char opt4[] = "priorities=a-b";
        char opt5[] = "priorities=100-a";
        char opt6[] = "priorities=100-100";
        char opt7[] = "priorities=0-100";
        char opt8[] = "priorities=100-0";

        assert_ok(bf_hookopts_new(&hookopts));
        assert_err(bf_hookopts_parse_opt(hookopts, opt1));
        assert_err(bf_hookopts_parse_opt(hookopts, opt2));
        assert_err(bf_hookopts_parse_opt(hookopts, opt3));
        assert_err(bf_hookopts_parse_opt(hookopts, opt4));
        assert_err(bf_hookopts_parse_opt(hookopts, opt5));
        assert_err(bf_hookopts_parse_opt(hookopts, opt6));
        assert_err(bf_hookopts_parse_opt(hookopts, opt7));
        assert_err(bf_hookopts_parse_opt(hookopts, opt8));
    }
}

static void hookopts_parse_unknown(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt1[] = "unknown=value";
    char opt2[] = "foo=bar";

    (void)state;

    assert_ok(bf_hookopts_new(&hookopts));

    // Test unknown options
    assert_err(bf_hookopts_parse_opt(hookopts, opt1));
    assert_err(bf_hookopts_parse_opt(hookopts, opt2));
}

static void hookopts_parse_invalid_format(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt1[] = "ifindex";
    char opt2[] = "invalidformat";

    (void)state;

    assert_ok(bf_hookopts_new(&hookopts));

    // Test missing equals sign
    assert_err(bf_hookopts_parse_opt(hookopts, opt1));
    assert_err(bf_hookopts_parse_opt(hookopts, opt2));
}

static void hookopts_validate_xdp(void **state)
{
    (void)state;

    // XDP requires ifindex
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        assert_ok(bf_hookopts_new(&hookopts));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_XDP));
    }

    // With ifindex, should be valid
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt[] = "ifindex=1";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_XDP));
    }

    // XDP doesn't support cgpath
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt1[] = "ifindex=1";
        char opt2[] = "cgpath=/sys/fs/cgroup";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt1));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt2));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_XDP));
    }
}

static void hookopts_validate_tc(void **state)
{
    (void)state;

    // TC requires ifindex
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        assert_ok(bf_hookopts_new(&hookopts));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_TC_INGRESS));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_TC_EGRESS));
    }

    // With ifindex, should be valid
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt[] = "ifindex=1";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_TC_INGRESS));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_TC_EGRESS));
    }
}

static void hookopts_validate_cgroup(void **state)
{
    (void)state;

    // Cgroup requires cgpath
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        assert_ok(bf_hookopts_new(&hookopts));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_CGROUP_INGRESS));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_CGROUP_EGRESS));
    }

    // With cgpath, should be valid
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt[] = "cgpath=/sys/fs/cgroup";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_CGROUP_INGRESS));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_CGROUP_EGRESS));
    }

    // Cgroup doesn't support ifindex
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt1[] = "cgpath=/sys/fs/cgroup";
        char opt2[] = "ifindex=1";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt1));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt2));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_CGROUP_INGRESS));
    }
}

static void hookopts_validate_nf(void **state)
{
    (void)state;

    // Netfilter requires family and priorities
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        assert_ok(bf_hookopts_new(&hookopts));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_NF_PRE_ROUTING));
    }

    // With only family
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt[] = "family=inet4";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt));
        assert_err(bf_hookopts_validate(hookopts, BF_HOOK_NF_PRE_ROUTING));
    }

    // With family and priorities, should be valid
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        char opt1[] = "family=inet4";
        char opt2[] = "priorities=100-200";
        assert_ok(bf_hookopts_new(&hookopts));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt1));
        assert_ok(bf_hookopts_parse_opt(hookopts, opt2));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_NF_PRE_ROUTING));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_NF_LOCAL_IN));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_NF_FORWARD));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_NF_LOCAL_OUT));
        assert_ok(bf_hookopts_validate(hookopts, BF_HOOK_NF_POST_ROUTING));
    }
}

static void hookopts_pack_and_unpack(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *source = NULL;
    _free_bf_hookopts_ struct bf_hookopts *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;
    char opt1[] = "ifindex=42";
    char opt2[] = "cgpath=/sys/fs/cgroup";
    char opt3[] = "family=inet4";
    char opt4[] = "priorities=100-200";

    (void)state;

    // Create and populate source hookopts
    assert_ok(bf_hookopts_new(&source));
    assert_ok(bf_hookopts_parse_opt(source, opt1));
    assert_ok(bf_hookopts_parse_opt(source, opt2));
    assert_ok(bf_hookopts_parse_opt(source, opt3));
    assert_ok(bf_hookopts_parse_opt(source, opt4));

    // Pack the source
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "hookopts");
    assert_ok(bf_hookopts_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "hookopts", &node));
    assert_ok(bf_hookopts_new_from_pack(&destination, node));

    // Verify all fields match
    assert_int_equal(destination->ifindex, source->ifindex);
    assert_string_equal(destination->cgpath, source->cgpath);
    assert_int_equal(destination->family, source->family);
    assert_int_equal(destination->priorities[0], source->priorities[0]);
    assert_int_equal(destination->priorities[1], source->priorities[1]);
    assert_int_equal(destination->used_opts, source->used_opts);
}

static void hookopts_pack_empty(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *source = NULL;
    _free_bf_hookopts_ struct bf_hookopts *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Create empty hookopts
    assert_ok(bf_hookopts_new(&source));

    // Pack the source
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "hookopts");
    assert_ok(bf_hookopts_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "hookopts", &node));
    assert_ok(bf_hookopts_new_from_pack(&destination, node));

    // Verify all fields are empty
    assert_int_equal(destination->used_opts, 0);
}

static void hookopts_dump(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt1[] = "ifindex=42";
    char opt2[] = "family=inet4";
    prefix_t prefix = {};

    (void)state;

    // Create and populate hookopts
    assert_ok(bf_hookopts_new(&hookopts));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt1));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt2));

    // Just verify dump doesn't crash
    bf_hookopts_dump(hookopts, &prefix);
}

static void hookopts_dump_all_options(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt1[] = "ifindex=42";
    char opt2[] = "cgpath=/sys/fs/cgroup";
    char opt3[] = "family=inet4";
    char opt4[] = "priorities=100-200";
    prefix_t prefix = {};

    (void)state;

    // Create and populate all options
    assert_ok(bf_hookopts_new(&hookopts));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt1));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt2));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt3));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt4));

    // Verify dump with all options doesn't crash
    bf_hookopts_dump(hookopts, &prefix);
}

static void hookopts_dump_empty(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    prefix_t prefix = {};

    (void)state;

    // Create empty hookopts
    assert_ok(bf_hookopts_new(&hookopts));

    // Verify dump with no options doesn't crash
    bf_hookopts_dump(hookopts, &prefix);
}

static void hookopts_dump_cgpath(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt[] = "cgpath=/sys/fs/cgroup/test";
    prefix_t prefix = {};

    (void)state;

    // Create hookopts with cgpath
    assert_ok(bf_hookopts_new(&hookopts));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt));

    // Verify dump with cgpath doesn't crash
    bf_hookopts_dump(hookopts, &prefix);
}

static void hookopts_dump_priorities(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    char opt[] = "priorities=100-200";
    prefix_t prefix = {};

    (void)state;

    // Create hookopts with priorities
    assert_ok(bf_hookopts_new(&hookopts));
    assert_ok(bf_hookopts_parse_opt(hookopts, opt));

    // Verify dump with priorities doesn't crash
    bf_hookopts_dump(hookopts, &prefix);
}

static void hookopts_parse_opts_list(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_list_ bf_list *opts = NULL;
    bf_list_ops free_ops = bf_list_ops_default(freep, NULL);
    char *opt1 = strdup("ifindex=42");
    char *opt2 = strdup("family=inet4");
    char *opt3 = strdup("priorities=100-200");

    (void)state;

    assert_non_null(opt1);
    assert_non_null(opt2);
    assert_non_null(opt3);

    // Create list of options
    assert_ok(bf_list_new(&opts, &free_ops));
    assert_ok(bf_list_push(opts, (void **)&opt1));
    assert_ok(bf_list_push(opts, (void **)&opt2));
    assert_ok(bf_list_push(opts, (void **)&opt3));

    // Parse all options from list
    assert_ok(bf_hookopts_new(&hookopts));
    assert_ok(bf_hookopts_parse_opts(hookopts, opts));

    // Verify all options were parsed (family is deprecated so not set)
    assert_int_equal(hookopts->ifindex, 42);
    assert_int_equal(hookopts->priorities[0], 100);
    assert_int_equal(hookopts->priorities[1], 200);
    assert_true(bf_hookopts_is_used(hookopts, BF_HOOKOPTS_IFINDEX));
    assert_true(bf_hookopts_is_used(hookopts, BF_HOOKOPTS_PRIORITIES));
}

static void hookopts_parse_opts_empty_list(void **state)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_list_ bf_list *opts = NULL;

    (void)state;

    // Parse empty list
    assert_ok(bf_hookopts_new(&hookopts));
    assert_ok(bf_list_new(&opts, NULL));
    assert_ok(bf_hookopts_parse_opts(hookopts, opts));
    assert_int_equal(hookopts->used_opts, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(hook_to_str),
        cmocka_unit_test(hook_from_str),
        cmocka_unit_test(hook_to_flavor),
        cmocka_unit_test(hook_to_bpf_attach_type),
        cmocka_unit_test(hook_to_bpf_prog_type),
        cmocka_unit_test(hook_to_nf_hook),
        cmocka_unit_test(hook_from_nf_hook),
        cmocka_unit_test(nf_hook_to_str),
        cmocka_unit_test(hookopts_new_and_free),
        cmocka_unit_test(hookopts_parse_ifindex),
        cmocka_unit_test(hookopts_parse_cgpath),
        cmocka_unit_test(hookopts_parse_family),
        cmocka_unit_test(hookopts_parse_priorities),
        cmocka_unit_test(hookopts_parse_unknown),
        cmocka_unit_test(hookopts_parse_invalid_format),
        cmocka_unit_test(hookopts_validate_xdp),
        cmocka_unit_test(hookopts_validate_tc),
        cmocka_unit_test(hookopts_validate_cgroup),
        cmocka_unit_test(hookopts_validate_nf),
        cmocka_unit_test(hookopts_pack_and_unpack),
        cmocka_unit_test(hookopts_pack_empty),
        cmocka_unit_test(hookopts_dump),
        cmocka_unit_test(hookopts_dump_all_options),
        cmocka_unit_test(hookopts_dump_empty),
        cmocka_unit_test(hookopts_dump_cgpath),
        cmocka_unit_test(hookopts_dump_priorities),
        cmocka_unit_test(hookopts_parse_opts_list),
        cmocka_unit_test(hookopts_parse_opts_empty_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
