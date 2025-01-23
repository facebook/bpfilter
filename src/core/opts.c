/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/opts.h"

#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/front.h"
#include "core/helper.h"
#include "core/logger.h"

enum
{
    BF_OPT_NO_IPTABLES_KEY,
    BF_OPT_NO_NFTABLES_KEY,
    BF_OPT_NO_CLI_KEY,
};

static const char *_bf_verbose_strs[] = {
    [BF_VERBOSE_DEBUG] = "debug",
    [BF_VERBOSE_BPF] = "bpf",
    [BF_VERBOSE_BYTECODE] = "bytecode",
};

static_assert(ARRAY_SIZE(_bf_verbose_strs) == _BF_VERBOSE_MAX,
              "missing entries in _bf_verbose_strs array");

int bf_verbose_to_str(const char *str, enum bf_verbose *opt)
{
    bf_assert(str && opt);

    for (size_t i = 0; i < _BF_VERBOSE_MAX; ++i) {
        if (bf_streq(_bf_verbose_strs[i], str)) {
            *opt = i;
            return 0;
        }
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
     * bpfilter is stopped, everything is cleaned up. */
    bool transient;

    /** Size of the log buffer when loading a BPF program, as a power of 2. */
    unsigned int bpf_log_buf_len_pow;

    /** Bit flags for enabled fronts. */
    uint16_t fronts;

    /** Verbose flags. Supported flags are:
     * - @c debug Print all the debug logs.
     * - @c bpf Add debug log messages in the generated BPF programs. */
    uint16_t verbose;
} _bf_opts = {
    .transient = false,
    .bpf_log_buf_len_pow = 16,
    .fronts = 0xffff,
    .verbose = 0,
};

static struct argp_option options[] = {
    {"transient", 't', 0, 0,
     "Do not load or save runtime context and remove all BPF programs on shutdown",
     0},
    {"buffer-len", 'b', "BUF_LEN_POW", 0,
     "Size of the BPF log buffer as a power of 2 (only used when --verbose is used). Default: 16.",
     0},
    {"no-iptables", BF_OPT_NO_IPTABLES_KEY, 0, 0, "Disable iptables support",
     0},
    {"no-nftables", BF_OPT_NO_NFTABLES_KEY, 0, 0, "Disable nftables support",
     0},
    {"no-cli", BF_OPT_NO_CLI_KEY, 0, 0, "Disable CLI support", 0},
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
    long pow;
    char *end;
    int r;

    switch (key) {
    case 't':
        args->transient = true;
        break;
    case 'b':
        errno = 0;
        pow = strtol(arg, &end, 0);
        if (errno == ERANGE) {
            return bf_err_r(EINVAL, "failed to convert '%s' into an integer",
                            arg);
        }
        if (pow > UINT_MAX) {
            return bf_err_r(EINVAL, "--buffer-len can't be bigger than %d",
                            UINT_MAX);
        }
        if (pow < 0)
            return bf_err_r(EINVAL, "--buffer-len can't be negative");
        args->bpf_log_buf_len_pow = (unsigned int)pow;
        break;
    case BF_OPT_NO_IPTABLES_KEY:
        bf_info("disabling iptables support");
        args->fronts &= ~(1 << BF_FRONT_IPT);
        break;
    case BF_OPT_NO_NFTABLES_KEY:
        bf_info("disabling nftables support");
        args->fronts &= ~(1 << BF_FRONT_NFT);
        break;
    case BF_OPT_NO_CLI_KEY:
        bf_info("disabling CLI support");
        args->fronts &= ~(1 << BF_FRONT_CLI);
        break;
    case 'v':
        r = bf_verbose_to_str(arg, &opt);
        if (r < 0)
            return bf_err_r(
                EINVAL,
                "unknown --verbose option '%s', valid --verbose options: [debug, bpf, bytecode]",
                arg);
        bf_info("enabling verbose for '%s'", arg);
        args->verbose |= (1 << opt);
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

unsigned int bf_opts_bpf_log_buf_len_pow(void)
{
    return _bf_opts.bpf_log_buf_len_pow;
}

bool bf_opts_is_front_enabled(enum bf_front front)
{
    return _bf_opts.fronts & (1 << front);
}

bool bf_opts_is_verbose(enum bf_verbose opt)
{
    return _bf_opts.verbose & (1 << opt);
}

void bf_opts_set_verbose(enum bf_verbose opt)
{
    _bf_opts.verbose |= (1 << opt);
}
