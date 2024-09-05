/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/opts.h"

#include <argp.h>
#include <errno.h>
#include <limits.h>
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
    BF_OPT_DEBUG_KEY,
};

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

    /** If true, print debug log messages (bf_debug). */
    bool verbose;

    /** If true, the BPF programs including log messages to be printed when
     * a BPF helper or kfunc fails.
     */
    bool debug;
} _bf_opts = {
    .transient = false,
    .bpf_log_buf_len_pow = 16,
    .fronts = 0xffff,
    .verbose = false,
    .debug = false,
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
    {"verbose", 'v', 0, 0, "Print debug logs", 0},
    {"debug", BF_OPT_DEBUG_KEY, 0, 0, "Generate BPF programs with debug logs",
     0},
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
    long pow;
    char *end;

    switch (key) {
    case 't':
        args->transient = true;
        break;
    case 'b':
        errno = 0;
        pow = strtol(arg, &end, 0);
        if (errno == ERANGE) {
            return bf_err_code(EINVAL, "failed to convert '%s' into an integer",
                               arg);
        }
        if (pow > UINT_MAX) {
            return bf_err_code(EINVAL, "--buffer-len can't be bigger than %d",
                               UINT_MAX);
        }
        if (pow < 0)
            return bf_err_code(EINVAL, "--buffer-len can't be negative");
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
        args->verbose = true;
        break;
    case BF_OPT_DEBUG_KEY:
        bf_info("generating BPF programs with debug logs");
        args->debug = true;
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

bool bf_opts_verbose(void)
{
    return _bf_opts.verbose;
}

bool bf_opts_debug(void)
{
    return _bf_opts.debug;
}
