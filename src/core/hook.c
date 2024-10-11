/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/hook.h"

#include <linux/bpf.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"

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
              "missing entries in hooks_str array");

const char *bf_hook_to_str(enum bf_hook hook)
{
    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);

    return _bf_hook_strs[hook];
}

int bf_hook_from_str(const char *str, enum bf_hook *hook)
{
    bf_assert(str);
    bf_assert(hook);

    for (size_t i = 0; i < _BF_HOOK_MAX; ++i) {
        if (bf_streq(_bf_hook_strs[i], str)) {
            *hook = i;
            return 0;
        }
    }

    return -EINVAL;
}

unsigned int bf_hook_to_bpf_prog_type(enum bf_hook hook)
{
    static const unsigned int prog_type[] = {
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

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(prog_type) == _BF_HOOK_MAX,
                  "missing entries in prog_type array");

    return prog_type[hook];
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

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(flavors) == _BF_HOOK_MAX,
                  "missing entries in flavors array");

    return flavors[hook];
}

enum bpf_attach_type bf_hook_to_attach_type(enum bf_hook hook)
{
    static const enum bpf_attach_type hooks[] = {
        [BF_HOOK_XDP] = 0,
        [BF_HOOK_TC_INGRESS] = BPF_TCX_INGRESS,
        [BF_HOOK_NF_PRE_ROUTING] = 0,
        [BF_HOOK_NF_LOCAL_IN] = BPF_NETFILTER,
        [BF_HOOK_CGROUP_INGRESS] = BPF_CGROUP_INET_INGRESS,
        [BF_HOOK_CGROUP_EGRESS] = BPF_CGROUP_INET_EGRESS,
        [BF_HOOK_NF_FORWARD] = BPF_NETFILTER,
        [BF_HOOK_NF_LOCAL_OUT] = BPF_NETFILTER,
        [BF_HOOK_NF_POST_ROUTING] = 0,
        [BF_HOOK_TC_EGRESS] = BPF_TCX_EGRESS,
    };

    bf_assert(0 <= hook && hook < _BF_HOOK_MAX);
    static_assert(ARRAY_SIZE(hooks) == _BF_HOOK_MAX,
                  "missing entries in hooks array");

    return hooks[hook];
}

static int _bf_hook_opt_ifindex_parse(struct bf_hook_opts *opts,
                                      const char *raw_opt)
{
    unsigned long ifindex;

    errno = 0;
    ifindex = strtoul(raw_opt, NULL, 0);
    if (errno != 0) {
        return bf_err_r(-errno, "failed to parse hook options ifindex=%s",
                        raw_opt);
    }

    if (ifindex > UINT_MAX)
        return bf_err_r(-E2BIG, "ifindex is too big: %lu", ifindex);

    opts->ifindex = (uint32_t)ifindex;

    return 0;
}

static void _bf_hook_opt_ifindex_dump(const struct bf_hook_opts *opts,
                                      prefix_t *prefix)
{
    DUMP(prefix, "ifindex: %d", opts->ifindex);
}

static int _bf_hook_opt_cgroup_parse(struct bf_hook_opts *opts,
                                     const char *raw_opt)
{
    opts->cgroup = strdup(raw_opt);
    if (!opts->cgroup)
        return bf_err_r(-ENOMEM, "failed to copy cgroup path '%s'", raw_opt);

    return 0;
}

static void _bf_hook_opt_cgroup_dump(const struct bf_hook_opts *opts,
                                     prefix_t *prefix)
{
    DUMP(prefix, "cgroup: %s", opts->cgroup);
}

static int _bf_hook_opt_name_parse(struct bf_hook_opts *opts,
                                   const char *raw_opt)
{
    if (strlen(raw_opt) >= BPF_OBJ_NAME_LEN) {
        return bf_err_r(E2BIG, "a chain name should be at most %d characters",
                        BPF_OBJ_NAME_LEN - 1);
    }

    opts->name = strdup(raw_opt);
    if (!opts->name)
        return bf_err_r(-ENOMEM, "failed to copy chain name '%s'", raw_opt);

    return 0;
}

static void _bf_hook_opt_name_dump(const struct bf_hook_opts *opts,
                                   prefix_t *prefix)
{
    DUMP(prefix, "name: %s", opts->name);
}

static int _bf_hook_opt_attach_parse(struct bf_hook_opts *opts,
                                   const char *raw_opt)
{
    if (bf_streq(raw_opt, "yes"))
        opts->attach = true;
    else if (bf_streq(raw_opt, "no"))
        opts->attach = false;
    else
        return bf_err_r(-EINVAL, "unknown attach value '%s'", raw_opt);

    return 0;
}

static void _bf_hook_opt_attach_dump(const struct bf_hook_opts *opts,
                                   prefix_t *prefix)
{
    DUMP(prefix, "attach: %s", opts->attach ? "yes" : "no");
}

static struct bf_hook_opt_support
{
    uint32_t required;
    uint32_t supported;
} _bf_hook_opts_support[] = {
    [BF_HOOK_XDP] =
        {
            .required = 1 << BF_HOOK_OPT_IFINDEX,
            .supported = 1 << BF_HOOK_OPT_IFINDEX | 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_TC_INGRESS] =
        {
            .required = 1 << BF_HOOK_OPT_IFINDEX,
            .supported = 1 << BF_HOOK_OPT_IFINDEX | 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_NF_PRE_ROUTING] =
        {
            .supported = 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_NF_LOCAL_IN] =
        {
            .supported = 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_CGROUP_INGRESS] =
        {
            .required = 1 << BF_HOOK_OPT_CGROUP,
            .supported = 1 << BF_HOOK_OPT_CGROUP | 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_CGROUP_EGRESS] =
        {
            .required = 1 << BF_HOOK_OPT_CGROUP,
            .supported = 1 << BF_HOOK_OPT_CGROUP | 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_NF_FORWARD] =
        {
            .supported = 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_NF_LOCAL_OUT] =
        {
            .supported = 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_NF_POST_ROUTING] =
        {
            .supported = 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
    [BF_HOOK_TC_EGRESS] =
        {
            .required = 1 << BF_HOOK_OPT_IFINDEX,
            .supported = 1 << BF_HOOK_OPT_IFINDEX | 1 << BF_HOOK_OPT_NAME | 1 << BF_HOOK_OPT_ATTACH,
        },
};

static_assert(ARRAY_SIZE(_bf_hook_opts_support) == _BF_HOOK_MAX,
              "missing entries in hook options support array");

static struct bf_hook_opt_ops
{
    const char *name;
    enum bf_hook_opt opt;
    int (*parse)(struct bf_hook_opts *opts, const char *raw_opt);
    void (*dump)(const struct bf_hook_opts *opts, prefix_t *prefix);
} _bf_hook_opt_ops[] = {
    {
        .name = "ifindex",
        .opt = BF_HOOK_OPT_IFINDEX,
        .parse = _bf_hook_opt_ifindex_parse,
        .dump = _bf_hook_opt_ifindex_dump,
    },
    {
        .name = "cgroup",
        .opt = BF_HOOK_OPT_CGROUP,
        .parse = _bf_hook_opt_cgroup_parse,
        .dump = _bf_hook_opt_cgroup_dump,
    },
    {
        .name = "name",
        .opt = BF_HOOK_OPT_NAME,
        .parse = _bf_hook_opt_name_parse,
        .dump = _bf_hook_opt_name_dump,
    },
    {
        .name = "attach",
        .opt = BF_HOOK_OPT_ATTACH,
        .parse = _bf_hook_opt_attach_parse,
        .dump = _bf_hook_opt_attach_dump,
    },
};

static_assert(ARRAY_SIZE(_bf_hook_opt_ops) == _BF_HOOK_OPT_MAX,
              "missing entries in hook option ops array");

#define _bf_hook_opt_is_supported(hook, opt)                                   \
    (_bf_hook_opts_support[hook].supported & (1 << (opt)))
#define _bf_hook_opt_is_required(hook, opt)                                    \
    (_bf_hook_opts_support[hook].required & (1 << (opt)))
#define _bf_hook_opt_is_used(opts, opt) ((opts)->used_opts & (1 << (opt)))

static struct bf_hook_opt_ops *_bf_hook_opts_get_ops(const char *key,
                                                     size_t len)
{
    int r;

    bf_assert(key && len > 0);

    for (int i = 0; i < _BF_HOOK_OPT_MAX; ++i) {
        r = strncmp(_bf_hook_opt_ops[i].name, key, len);
        if (r == 0)
            return &_bf_hook_opt_ops[i];
    }

    return NULL;
}

static int _bf_hook_opts_process_opts(struct bf_hook_opts *opts,
                                      enum bf_hook hook, bf_list *raw_opts)
{
    const char *value;
    const struct bf_hook_opt_ops *ops;
    int r;

    bf_assert(opts);

    if (!raw_opts)
        return 0;

    bf_list_foreach (raw_opts, raw_opt_node) {
        const char *raw_opt = bf_list_node_get_data(raw_opt_node);

        value = strchr(raw_opt, '=');

        ops = _bf_hook_opts_get_ops(raw_opt, value - raw_opt);
        if (!ops)
            return bf_err_r(-ENOTSUP, "unknown option '%s', ignoring", raw_opt);

        if (!_bf_hook_opt_is_supported(hook, ops->opt)) {
            return bf_err_r(-ENOTSUP, "hook '%s' doesn't support option '%s'",
                            bf_hook_to_str(hook), ops->name);
        }

        r = ops->parse(opts, value + 1);
        if (r < 0)
            return r;

        opts->used_opts |= (1 << ops->opt);
    }

    return 0;
}

int bf_hook_opts_init(struct bf_hook_opts *opts, enum bf_hook hook,
                      bf_list *raw_opts)
{
    int r;

    bf_assert(opts);

    *opts = (struct bf_hook_opts) {
        .used_opts = 1 << BF_HOOK_OPT_ATTACH,
        .attach = true,
    };

    r = _bf_hook_opts_process_opts(opts, hook, raw_opts);
    if (r < 0)
        return r;

    for (int i = 0; i < _BF_HOOK_OPT_MAX; ++i) {
        if (_bf_hook_opt_is_required(hook, i) &&
            !_bf_hook_opt_is_used(opts, i)) {
            return bf_err_r(-EINVAL, "hook '%s' requires option '%s'",
                            bf_hook_to_str(hook), _bf_hook_opt_ops[i].name);
        }
    }

    return 0;
}

void bf_hook_opts_clean(struct bf_hook_opts *opts)
{
    freep((void *)&opts->cgroup);
    freep((void *)&opts->name);
}

void bf_hook_opts_dump(const struct bf_hook_opts *opts, prefix_t *prefix,
                       enum bf_hook hook)
{
    DUMP(prefix, "struct bf_hook_opts at %p", opts);
    bf_dump_prefix_push(prefix);

    for (int i = 0; i < _BF_HOOK_OPT_MAX; ++i) {
        struct bf_hook_opt_ops *ops = &_bf_hook_opt_ops[i];
        if (i == _BF_HOOK_OPT_MAX - 1)
            bf_dump_prefix_last(prefix);

        if (!_bf_hook_opt_is_supported(hook, i)) {
            DUMP(prefix, "%s: <unsupported>", ops->name);
        } else if (!_bf_hook_opt_is_used(opts, i)) {
            DUMP(prefix, "%s: <unset>", ops->name);
        } else {
            ops->dump(opts, prefix);
        }
    }

    bf_dump_prefix_pop(prefix);
}
