/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "opts.h"

#include <argp.h>
#include <stdint.h>

#include "core/logger.h"
#include "shared/helper.h"

/**
 * @brief bpfilter runtime configuration
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
} _opts = {
    .transient = false,
    .bpf_log_buf_len_pow = 16,
    .fronts = 0xffff,
    .verbose = false,
};

static struct argp_option options[] = {
    {"transient", 't', 0, 0,
     "Do not load or save runtime context and remove all BPF programs on shutdown",
     0},
    {"buffer-len", 'b', "BUF_LEN_POW", 0,
     "Size of the BPF log buffer as a power of 2 (only used when --verbose is used). Default: 16.",
     0},
    {"no-iptables", 0x01, 0, 0, "Disable iptables support", 0},
    {"no-nftables", 0x02, 0, 0, "Disable nftables support", 0},
    {"verbose", 'v', 0, 0, "Print debug logs", 0},
    {0},
};

/**
 * @brief argp callback to process command line arguments.
 *
 * @return 0 on succcess, non-zero on failure.
 */
static error_t _bf_opts_parser(int key, char *arg, struct argp_state *state)
{
    UNUSED(arg);

    struct bf_options *args = state->input;

    switch (key) {
    case 't':
        args->transient = true;
        break;
    case 'b':
        args->bpf_log_buf_len_pow = atoi(arg);
        break;
    case 0x01:
        bf_info("disabling iptables support");
        args->fronts &= ~(1 << BF_FRONT_IPT);
        break;
    case 0x02:
        bf_info("disabling nftables support");
        args->fronts &= ~(1 << BF_FRONT_NFT);
        break;
    case 'v':
        args->verbose = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int bf_opts_init(int argc, char *argv[])
{
    struct argp argp = {options, _bf_opts_parser, NULL, NULL, 0, NULL, NULL};

    return argp_parse(&argp, argc, argv, 0, 0, &_opts);
}

bool bf_opts_transient(void)
{
    return _opts.transient;
}

unsigned int bf_opts_bpf_log_buf_len_pow(void)
{
    return _opts.bpf_log_buf_len_pow;
}

bool bf_opts_is_front_enabled(enum bf_front front)
{
    return _opts.fronts & (1 << front);
}

bool bf_opts_verbose(void)
{
    return _opts.verbose;
}
