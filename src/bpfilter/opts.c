/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "opts.h"

#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <bpfilter/front.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#define BF_DEFAULT_BPFFS_PATH "/sys/fs/bpf"

enum
{
    BF_OPT_NO_IPTABLES_KEY,
    BF_OPT_NO_NFTABLES_KEY,
    BF_OPT_NO_CLI_KEY,
    BF_OPT_WITH_BPF_TOKEN,
    BF_OPT_BPFFS_PATH,
    BF_OPT_VERSION,
};

static const char *_bf_verbose_strs[] = {
    [BF_VERBOSE_DEBUG] = "debug",
    [BF_VERBOSE_BPF] = "bpf",
    [BF_VERBOSE_BYTECODE] = "bytecode",
};

static_assert(ARRAY_SIZE(_bf_verbose_strs) == _BF_VERBOSE_MAX,
              "missing entries in _bf_verbose_strs array");

enum bf_verbose bf_verbose_from_str(const char *str)
{
    bf_assert(str);

    for (enum bf_verbose verbose = 0; verbose < _BF_VERBOSE_MAX; ++verbose) {
        if (bf_streq(_bf_verbose_strs[verbose], str))
            return verbose;
    }

    return -EINVAL;
}

/**
 * bpfilter runtime configuration
 */
static struct bf_options
{
    /** If true, bpfilter won't load or save its state to the filesystem, and
     * all the loaded BPF programs will be unloaded before shuting down. Hence,
     * as long as bpfilter is running, filtering rules will be applied. When
     * bpfilter is stopped, everything is cleaned up.
     *
     * @todo Validate the daemon's behaviour when switch to and from
     * ``--transient``. */
    bool transient;

    /** Pass a token to BPF system calls, obtained from bpffs. */
    bool with_bpf_token;

    /** Path to the bpffs to pin the BPF objects into. */
    const char *bpffs_path;

    /** Bit flags for enabled fronts. */
    uint16_t fronts;

    /** Verbose flags. Supported flags are:
     * - @c debug Print all the debug logs.
     * - @c bpf Add debug log messages in the generated BPF programs. */
    uint16_t verbose;
} _bf_opts = {
    .transient = false,
    .with_bpf_token = false,
    .bpffs_path = BF_DEFAULT_BPFFS_PATH,
    .fronts = 0xffff,
    .verbose = 0,
};

static struct argp_option options[] = {
    {"transient", 't', 0, 0,
     "Do not load or save runtime context and remove all BPF programs on shutdown",
     0},
    {"buffer-len", 'b', "BUF_LEN_POW", 0,
     "DEPRECATED. Size of the BPF log buffer as a power of 2 (only used when --verbose is used). Default: 16.",
     0},
    {"no-iptables", BF_OPT_NO_IPTABLES_KEY, 0, 0, "Disable iptables support",
     0},
    {"no-nftables", BF_OPT_NO_NFTABLES_KEY, 0, 0, "Disable nftables support",
     0},
    {"no-cli", BF_OPT_NO_CLI_KEY, 0, 0, "Disable CLI support", 0},
    {"with-bpf-token", BF_OPT_WITH_BPF_TOKEN, NULL, 0,
     "Use a BPF token with the bpf() system calls. The token is created from the bpffs instance mounted at /sys/fs/bpf.",
     0},
    {"bpffs-path", BF_OPT_BPFFS_PATH, "BPFFS_PATH", 0,
     "Path to the bpffs to pin the BPF objects into. Defaults to " BF_DEFAULT_BPFFS_PATH
     ".",
     0},
    {"verbose", 'v', "VERBOSE_FLAG", 0,
     "Verbose flags to enable. Can be used more than once.", 0},
    {0},
};

/**
 * argp callback to process command line arguments.
 *
 * @return 0 on succcess, non-zero on failure.
 */
static error_t _bf_opts_parser(int key, char *arg, struct argp_state *state)
{
    UNUSED(arg);

    struct bf_options *args = state->input;
    enum bf_verbose opt;

    switch (key) {
    case 't':
        args->transient = true;
        break;
    case 'b':
        bf_warn(
            "--buffer-len is deprecated, buffer size is defined automatically");
        break;
    case BF_OPT_NO_IPTABLES_KEY:
        bf_info("disabling iptables support");
        args->fronts &= ~BF_FLAG(BF_FRONT_IPT);
        break;
    case BF_OPT_NO_NFTABLES_KEY:
        bf_info("disabling nftables support");
        args->fronts &= ~BF_FLAG(BF_FRONT_NFT);
        break;
    case BF_OPT_NO_CLI_KEY:
        bf_info("disabling CLI support");
        args->fronts &= ~BF_FLAG(BF_FRONT_CLI);
        break;
    case BF_OPT_WITH_BPF_TOKEN:
        args->with_bpf_token = true;
        bf_info("using a BPF token");
        break;
    case BF_OPT_BPFFS_PATH:
        args->bpffs_path = arg;
        bf_info("using bpffs at %s", args->bpffs_path);
        break;
    case 'v':
        opt = bf_verbose_from_str(arg);
        if ((int)opt < 0) {
            return bf_err_r(
                (int)opt,
                "unknown --verbose option '%s', valid --verbose options: [debug, bpf, bytecode]",
                arg);
        }
        bf_info("enabling verbose for '%s'", arg);
        if (opt == BF_VERBOSE_DEBUG)
            bf_log_set_level(BF_LOG_DBG);
        args->verbose |= BF_FLAG(opt);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int bf_opts_init(int argc, char *argv[])
{
    struct argp argp = {options, _bf_opts_parser, NULL, NULL, 0, NULL, NULL};

    return argp_parse(&argp, argc, argv, 0, 0, &_bf_opts);
}

bool bf_opts_transient(void)
{
    return _bf_opts.transient;
}

bool bf_opts_persist(void)
{
    return !_bf_opts.transient;
}

bool bf_opts_is_front_enabled(enum bf_front front)
{
    return _bf_opts.fronts & BF_FLAG(front);
}

bool bf_opts_with_bpf_token(void)
{
    return _bf_opts.with_bpf_token;
}

const char *bf_opts_bpffs_path(void)
{
    return _bf_opts.bpffs_path;
}

bool bf_opts_is_verbose(enum bf_verbose opt)
{
    return _bf_opts.verbose & BF_FLAG(opt);
}

void bf_opts_set_verbose(enum bf_verbose opt)
{
    _bf_opts.verbose |= BF_FLAG(opt);
}
