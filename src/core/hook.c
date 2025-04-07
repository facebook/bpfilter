/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/hook.h"

#include <linux/bpf.h>
#include <linux/netfilter.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "core/dump.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"

static const char *_bf_hook_strs[] = {
    [BF_HOOK_XDP] = "BF_HOOK_XDP",
    [BF_HOOK_TC_INGRESS] = "BF_HOOK_TC_INGRESS",
    [BF_HOOK_NF_PRE_ROUTING] = "BF_HOOK_NF_PRE_ROUTING",
    [BF_HOOK_NF_LOCAL_IN] = "BF_HOOK_NF_LOCAL_IN",
    [BF_HOOK_CGROUP_INGRESS] = "BF_HOOK_CGROUP_INGRESS",
    [BF_HOOK_CGROUP_EGRESS] = "BF_HOOK_CGROUP_EGRESS",
    [BF_HOOK_NF_FORWARD] = "BF_HOOK_NF_FORWARD",
    [BF_HOOK_NF_LOCAL_OUT] = "BF_HOOK_NF_LOCAL_OUT",
    [BF_HOOK_NF_POST_ROUTING] = "BF_HOOK_NF_POST_ROUTING",
    [BF_HOOK_TC_EGRESS] = "BF_HOOK_TC_EGRESS",
};
static_assert(ARRAY_SIZE(_bf_hook_strs) == _BF_HOOK_MAX,
              "missing entries in bf_hook strings array");

const char *bf_hook_to_str(enum bf_hook hook)
{
    return _bf_hook_strs[hook];
}

enum bf_hook bf_hook_from_str(const char *str)
{
    bf_assert(str);

    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook) {
        if (bf_streq(_bf_hook_strs[hook], str))
            return hook;
    }

    return -EINVAL;
}

enum bf_flavor bf_hook_to_flavor(enum bf_hook hook)
{
    static const enum bf_flavor flavors[] = {
        [BF_HOOK_XDP] = BF_FLAVOR_XDP,
        [BF_HOOK_TC_INGRESS] = BF_FLAVOR_TC,
        [BF_HOOK_NF_PRE_ROUTING] = BF_FLAVOR_NF,
        [BF_HOOK_NF_LOCAL_IN] = BF_FLAVOR_NF,
        [BF_HOOK_CGROUP_INGRESS] = BF_FLAVOR_CGROUP,
        [BF_HOOK_CGROUP_EGRESS] = BF_FLAVOR_CGROUP,
        [BF_HOOK_NF_FORWARD] = BF_FLAVOR_NF,
        [BF_HOOK_NF_LOCAL_OUT] = BF_FLAVOR_NF,
        [BF_HOOK_NF_POST_ROUTING] = BF_FLAVOR_NF,
        [BF_HOOK_TC_EGRESS] = BF_FLAVOR_TC,
    };

    static_assert(ARRAY_SIZE(flavors) == _BF_HOOK_MAX,
                  "missing entries in bf_flavor array");

    return flavors[hook];
}

enum bpf_attach_type bf_hook_to_bpf_attach_type(enum bf_hook hook)
{
    static const enum bpf_attach_type attach_types[] = {
        [BF_HOOK_XDP] = 0,
        [BF_HOOK_TC_INGRESS] = BPF_TCX_INGRESS,
        [BF_HOOK_NF_PRE_ROUTING] = BPF_NETFILTER,
        [BF_HOOK_NF_LOCAL_IN] = BPF_NETFILTER,
        [BF_HOOK_CGROUP_INGRESS] = BPF_CGROUP_INET_INGRESS,
        [BF_HOOK_CGROUP_EGRESS] = BPF_CGROUP_INET_EGRESS,
        [BF_HOOK_NF_FORWARD] = BPF_NETFILTER,
        [BF_HOOK_NF_LOCAL_OUT] = BPF_NETFILTER,
        [BF_HOOK_NF_POST_ROUTING] = BPF_NETFILTER,
        [BF_HOOK_TC_EGRESS] = BPF_TCX_EGRESS,
    };

    static_assert(ARRAY_SIZE(attach_types) == _BF_HOOK_MAX,
                  "missing entries in bpf_attach_type array");

    return attach_types[hook];
}

enum bpf_prog_type bf_hook_to_bpf_prog_type(enum bf_hook hook)
{
    static const enum bpf_prog_type prog_types[] = {
        [BF_HOOK_XDP] = BPF_PROG_TYPE_XDP,
        [BF_HOOK_TC_INGRESS] = BPF_PROG_TYPE_SCHED_CLS,
        [BF_HOOK_NF_PRE_ROUTING] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_NF_LOCAL_IN] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_CGROUP_INGRESS] = BPF_PROG_TYPE_CGROUP_SKB,
        [BF_HOOK_CGROUP_EGRESS] = BPF_PROG_TYPE_CGROUP_SKB,
        [BF_HOOK_NF_FORWARD] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_NF_LOCAL_OUT] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_NF_POST_ROUTING] = BPF_PROG_TYPE_NETFILTER,
        [BF_HOOK_TC_EGRESS] = BPF_PROG_TYPE_SCHED_CLS,
    };

    static_assert(ARRAY_SIZE(prog_types) == _BF_HOOK_MAX,
                  "missing entries in bpf_prog_type array");

    return prog_types[hook];
}

enum nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook)
{
    switch (hook) {
    case BF_HOOK_NF_PRE_ROUTING:
        return NF_INET_PRE_ROUTING;
    case BF_HOOK_NF_LOCAL_IN:
        return NF_INET_LOCAL_IN;
    case BF_HOOK_NF_FORWARD:
        return NF_INET_FORWARD;
    case BF_HOOK_NF_LOCAL_OUT:
        return NF_INET_LOCAL_OUT;
    case BF_HOOK_NF_POST_ROUTING:
        return NF_INET_POST_ROUTING;
    default:
        bf_warn("bf_hook %s (%d) is not an nf_inet_hooks value",
                bf_hook_to_str(hook), hook);
        return -EINVAL;
    }
}

enum bf_hook bf_hook_from_nf_hook(enum nf_inet_hooks hook)
{
    switch (hook) {
    case NF_INET_PRE_ROUTING:
        return BF_HOOK_NF_PRE_ROUTING;
    case NF_INET_LOCAL_IN:
        return BF_HOOK_NF_LOCAL_IN;
    case NF_INET_FORWARD:
        return BF_HOOK_NF_FORWARD;
    case NF_INET_LOCAL_OUT:
        return BF_HOOK_NF_LOCAL_OUT;
    case NF_INET_POST_ROUTING:
        return BF_HOOK_NF_POST_ROUTING;
    default:
        bf_warn("nf_inet_hooks %s (%d) is not a bf_hook value",
                bf_nf_hook_to_str(hook), hook);
        return -EINVAL;
    }
}

const char *bf_nf_hook_to_str(enum nf_inet_hooks hook)
{
    switch (hook) {
    case NF_INET_PRE_ROUTING:
        return "nf_prerouting";
    case NF_INET_LOCAL_IN:
        return "nf_input";
    case NF_INET_FORWARD:
        return "nf_forward";
    case NF_INET_LOCAL_OUT:
        return "nf_output";
    case NF_INET_POST_ROUTING:
        return "nf_postrouting";
    default:
        bf_warn("unknown nf_inet_hooks value %d", hook);
        return NULL;
    }
}

static int _bf_hookopts_ifindex_parse(struct bf_hookopts *hookopts,
                                      const char *raw_opt)
{
    unsigned long ifindex;

    bf_assert(hookopts && raw_opt);

    errno = 0;
    ifindex = strtoul(raw_opt, NULL, 0);
    if (errno != 0) {
        return bf_err_r(-errno, "failed to parse bf_hookopts type ifindex=%s",
                        raw_opt);
    }

    if (ifindex > INT_MAX)
        return bf_err_r(-E2BIG, "ifindex is too big: %lu", ifindex);

    hookopts->ifindex = (int)ifindex;
    hookopts->used_opts |= 1 << BF_HOOKOPTS_IFINDEX;

    return 0;
}

static void _bf_hookopts_ifindex_dump(const struct bf_hookopts *hookopts,
                                      prefix_t *prefix)
{
    bf_assert(hookopts && prefix);

    DUMP(prefix, "ifindex: %d", hookopts->ifindex);
}

static int _bf_hookopts_cgpath_parse(struct bf_hookopts *hookopts,
                                     const char *raw_opt)
{
    bf_assert(hookopts && raw_opt);

    hookopts->cgpath = strdup(raw_opt);
    if (!hookopts->cgpath) {
        return bf_err_r(-ENOMEM, "failed to copy hook option cgpath=%s",
                        raw_opt);
    }

    hookopts->used_opts |= 1 << BF_HOOKOPTS_CGPATH;

    return 0;
}

static void _bf_hookopts_cgpath_dump(const struct bf_hookopts *hookopts,
                                     prefix_t *prefix)
{
    bf_assert(hookopts && prefix);

    DUMP(prefix, "cgpath: %s", hookopts->cgpath);
}

static int _bf_hookopts_family_parse(struct bf_hookopts *hookopts,
                                     const char *raw_opt)
{
    bf_assert(hookopts && raw_opt);

    if (bf_streq("inet4", raw_opt))
        hookopts->family = PF_INET;
    else if (bf_streq("inet6", raw_opt))
        hookopts->family = PF_INET6;
    else
        return bf_err_r(-ENOTSUP, "unknown netfilter family '%s'", raw_opt);

    hookopts->used_opts |= 1 << BF_HOOKOPTS_FAMILY;

    return 0;
}

static void _bf_hookopts_family_dump(const struct bf_hookopts *hookopts,
                                     prefix_t *prefix)
{
    bf_assert(hookopts && prefix);

    DUMP(prefix, "family: %s", hookopts->family == PF_INET ? "inet4" : "inet6");
}

static int _bf_hookopts_priorities_parse(struct bf_hookopts *hookopts,
                                         const char *raw_opt)
{
    unsigned long priorities[2];
    _cleanup_free_ char *copy = NULL;
    char *right, *end;

    bf_assert(hookopts && raw_opt);

    copy = strdup(raw_opt);
    if (!copy)
        return -ENOMEM;

    end = copy + strlen(copy);

    right = strchr(copy, '-');
    if (!right)
        goto err_parsing;

    *right = '\0';
    ++right;
    if (end <= right)
        goto err_parsing;

    errno = 0;
    priorities[0] = strtoul(copy, NULL, 0);
    if (errno != 0)
        goto err_parsing;

    priorities[1] = strtoul(right, NULL, 0);
    if (errno != 0)
        goto err_parsing;

    if (priorities[0] > INT_MAX || priorities[1] > INT_MAX)
        return bf_err_r(-EINVAL, "priorities can't be bigger than %d", INT_MAX);

    if (priorities[0] == priorities[1])
        return bf_err_r(-EINVAL, "priorities must be different");

    if (!priorities[0] || !priorities[1])
        return bf_err_r(-EINVAL, "priorities can't be 0");

    hookopts->priorities[0] = (int)priorities[0];
    hookopts->priorities[1] = (int)priorities[1];
    hookopts->used_opts |= 1 << BF_HOOKOPTS_PRIORITIES;

    return 0;

err_parsing:
    return bf_err_r(-EINVAL, "failed to parse '%s', expecting '$INT-$INT'",
                    raw_opt);
}

static void _bf_hookopts_priorities_dump(const struct bf_hookopts *hookopts,
                                         prefix_t *prefix)
{
    bf_assert(hookopts && prefix);

    DUMP(prefix, "priorities: %d, %d", hookopts->priorities[0],
         hookopts->priorities[1]);
}

static struct bf_hookopts_ops
{
    const char *name;
    enum bf_hookopts_type type;
    uint32_t supported_by;
    uint32_t required_by;
    int (*parse)(struct bf_hookopts *, const char *);
    void (*dump)(const struct bf_hookopts *, prefix_t *);
} _bf_hookopts_ops[] = {
    [BF_HOOKOPTS_IFINDEX] = {.name = "ifindex",
                             .type = BF_HOOKOPTS_IFINDEX,
                             .required_by =
                                 1 << BF_FLAVOR_XDP | 1 << BF_FLAVOR_TC,
                             .supported_by = 0,
                             .parse = _bf_hookopts_ifindex_parse,
                             .dump = _bf_hookopts_ifindex_dump},
    [BF_HOOKOPTS_CGPATH] = {.name = "cgpath",
                            .type = BF_HOOKOPTS_CGPATH,
                            .required_by = 1 << BF_FLAVOR_CGROUP,
                            .supported_by = 0,
                            .parse = _bf_hookopts_cgpath_parse,
                            .dump = _bf_hookopts_cgpath_dump},
    [BF_HOOKOPTS_FAMILY] = {.name = "family",
                            .type = BF_HOOKOPTS_FAMILY,
                            .required_by = 1 << BF_FLAVOR_NF,
                            .supported_by = 0,
                            .parse = _bf_hookopts_family_parse,
                            .dump = _bf_hookopts_family_dump},
    [BF_HOOKOPTS_PRIORITIES] = {.name = "priorities",
                                .type = BF_HOOKOPTS_PRIORITIES,
                                .required_by = 1 << BF_FLAVOR_NF,
                                .supported_by = 0,
                                .parse = _bf_hookopts_priorities_parse,
                                .dump = _bf_hookopts_priorities_dump},
};

static_assert(ARRAY_SIZE(_bf_hookopts_ops) == _BF_HOOKOPTS_MAX,
              "missing entries in bf_hookopts_ops array");

#define _bf_hookopts_is_required(type, flavor)                                 \
    (_bf_hookopts_ops[type].required_by & (1 << (flavor)))

#define _bf_hookopts_is_supported(type, flavor)                                \
    ((_bf_hookopts_ops[type].supported_by & (1 << (flavor))) ||                \
     _bf_hookopts_is_required((type), (flavor)))

static struct bf_hookopts_ops *_bf_hookopts_get_ops(const char *key)
{
    bf_assert(key);

    for (enum bf_hookopts_type type = 0; type < _BF_HOOKOPTS_MAX; ++type) {
        if (bf_streq(_bf_hookopts_ops[type].name, key))
            return &_bf_hookopts_ops[type];
    }

    return NULL;
}

int bf_hookopts_new(struct bf_hookopts **hookopts)
{
    bf_assert(hookopts);

    *hookopts = calloc(1, sizeof(struct bf_hookopts));
    if (!*hookopts)
        return bf_err_r(-ENOMEM, "failed to allocate a new bf_hookopts object");

    return 0;
}

int bf_hookopts_new_from_marsh(struct bf_hookopts **hookopts,
                               const struct bf_marsh *marsh)
{
    _free_bf_hookopts_ struct bf_hookopts *_hookopts = NULL;
    struct bf_marsh *child = NULL;
    int r;

    bf_assert(hookopts && marsh);

    r = bf_hookopts_new(&_hookopts);
    if (r)
        return r;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return bf_err_r(-EINVAL, "bf_hookopts: missing used_opts field");
    memcpy(&_hookopts->used_opts, child->data, sizeof(_hookopts->used_opts));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return bf_err_r(-EINVAL, "bf_hookopts: missing ifindex field");
    memcpy(&_hookopts->ifindex, child->data, sizeof(_hookopts->ifindex));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return bf_err_r(-EINVAL, "bf_hookopts: missing cgpath field");
    if (child->data_len) {
        _hookopts->cgpath = strdup(child->data);
        if (!_hookopts->cgpath)
            return -ENOMEM;
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return bf_err_r(-EINVAL, "bf_hookopts: missing family field");
    memcpy(&_hookopts->family, child->data, sizeof(_hookopts->family));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return bf_err_r(-EINVAL, "bf_hookopts: missing priorities field");
    memcpy(&_hookopts->priorities, child->data, sizeof(_hookopts->priorities));

    if (bf_marsh_next_child(marsh, child))
        return bf_err_r(-E2BIG, "too many serialized fields for bf_hookopts");

    *hookopts = TAKE_PTR(_hookopts);

    return 0;
}

void bf_hookopts_free(struct bf_hookopts **hookopts)
{
    bf_assert(hookopts);

    if (!*hookopts)
        return;

    freep((void *)&(*hookopts)->cgpath);
    freep((void *)hookopts);
}

int bf_hookopts_marsh(const struct bf_hookopts *hookopts,
                      struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r = 0;

    bf_assert(hookopts && marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return bf_err_r(r, "failed to create a new marsh for bf_hookopts");

    r = bf_marsh_add_child_raw(&_marsh, &hookopts->used_opts,
                               sizeof(hookopts->used_opts));
    if (r)
        return bf_err_r(r, "failed to marsh bf_hookopts.used_opts");

    r = bf_marsh_add_child_raw(&_marsh, &hookopts->ifindex,
                               sizeof(hookopts->ifindex));
    if (r)
        return bf_err_r(r, "failed to marsh bf_hookopts.ifindex");

    r = bf_marsh_add_child_raw(&_marsh, hookopts->cgpath,
                               hookopts->cgpath ? strlen(hookopts->cgpath) + 1 :
                                                  0);
    if (r)
        return bf_err_r(r, "failed to marsh bf_hookopts.cgpath");

    r = bf_marsh_add_child_raw(&_marsh, &hookopts->family,
                               sizeof(hookopts->family));
    if (r)
        return bf_err_r(r, "failed to marsh bf_hookopts.family");

    r = bf_marsh_add_child_raw(&_marsh, hookopts->priorities,
                               sizeof(hookopts->priorities));
    if (r)
        return bf_err_r(r, "failed to marsh bf_hookopts.priorities");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_hookopts_dump(const struct bf_hookopts *hookopts, prefix_t *prefix)
{
    bf_assert(hookopts && prefix);

    DUMP(prefix, "struct bf_hookopts at %p", hookopts);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "used_opts: 0x%08x", hookopts->used_opts);

    for (enum bf_hookopts_type type = 0; type < _BF_HOOKOPTS_MAX; ++type) {
        if (type == _BF_HOOKOPTS_MAX - 1)
            bf_dump_prefix_last(prefix);

        if (bf_hookopts_is_used(hookopts, type))
            _bf_hookopts_ops[type].dump(hookopts, prefix);
        else
            DUMP(prefix, "%s: <unset>", _bf_hookopts_ops[type].name);
    }

    bf_dump_prefix_pop(prefix);
}

int bf_hookopts_parse_opt(struct bf_hookopts *hookopts, const char *raw_opt)
{
    char *value;
    struct bf_hookopts_ops *ops;
    int r;

    bf_assert(hookopts && raw_opt);

    value = strchr(raw_opt, '=');
    if (!value)
        return -ENOENT;

    *value = '\0';
    ++value;

    ops = _bf_hookopts_get_ops(raw_opt);
    if (!ops) {
        return bf_err_r(-ENOTSUP, "unknown hook option '%s', ignoring",
                        raw_opt);
    }

    r = ops->parse(hookopts, value);
    if (r < 0)
        return r;

    return 0;
}

int bf_hookopts_parse_opts(struct bf_hookopts *hookopts, bf_list *raw_opts)
{
    int r;

    bf_assert(hookopts && raw_opts);

    if (!raw_opts)
        return 0;

    bf_list_foreach (raw_opts, raw_opt_node) {
        r = bf_hookopts_parse_opt(hookopts,
                                  bf_list_node_get_data(raw_opt_node));
        if (r)
            return r;
    }

    return 0;
}

int bf_hookopts_validate(const struct bf_hookopts *hookopts, enum bf_hook hook)
{
    enum bf_flavor flavor = bf_hook_to_flavor(hook);

    bf_assert(hookopts);

    for (enum bf_hookopts_type type = 0; type < _BF_HOOKOPTS_MAX; ++type) {
        struct bf_hookopts_ops *ops = &_bf_hookopts_ops[type];
        bool is_used = bf_hookopts_is_used(hookopts, type);
        bool is_required = _bf_hookopts_is_required(type, flavor);
        bool is_supported = _bf_hookopts_is_supported(type, flavor);

        if (is_required && !is_used) {
            return bf_err_r(-EINVAL,
                            "hook option '%s' is required for '%s' chains",
                            ops->name, bf_hook_to_str(hook));
        }

        if (is_used && !(is_supported | is_required)) {
            return bf_err_r(-ENOTSUP,
                            "hook option '%s' is not supported for '%s' chains",
                            ops->name, bf_hook_to_str(hook));
        }
    }

    return 0;
}
