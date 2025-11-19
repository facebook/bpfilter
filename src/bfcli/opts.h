/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include <bpfilter/hook.h>

/**
 * @file opts.h
 *
 * bfcli commands are constructed as `bfcli OBJECT ACTION [OPTIONS...]`, with
 * `OBJECT` the type of bpfilter object to manipulate, and `ACTION` the action
 * to apply to the object.
 *
 * This file provides the mechanism to define and parse command line object for
 * all the existing commands supported by bfcli.
 *
 * Two `argp.h` parsers are required to parse bfcli commands. The first parser
 * will validate the `OBJECT` and `ACTION`. The second parser is constructed
 * based on `OBJECT` and `ACTION` to only parse the options supported by this
 * specific command.
 */

#define _clean_bfc_opts_ __attribute__((__cleanup__(bfc_opts_clean)))

/**
 * @brief Type of objects supported by bfcli
 */
enum bfc_object
{
    BFC_OBJECT_RULESET,
    BFC_OBJECT_CHAIN,
    _BFC_OBJECT_MAX,
};

/**
 * @brief Type of actions supported by bfcli
 */
enum bfc_action
{
    BFC_ACTION_SET,
    BFC_ACTION_GET,
    BFC_ACTION_LOGS,
    BFC_ACTION_LOAD,
    BFC_ACTION_ATTACH,
    BFC_ACTION_UPDATE,
    BFC_ACTION_FLUSH,
    _BFC_ACTION_MAX,
};

struct bfc_opts_cmd;

/**
 * @brief Command line options configured for bfcli
 */
struct bfc_opts
{
    const struct bfc_opts_cmd *cmd;

    enum bfc_object object;
    enum bfc_action action;

    uint32_t set_opts;

    const char *from_str;
    const char *from_file;
    const char *name;
    struct bf_hookopts hookopts;

    bool dry_run;
};

struct bfc_opts_cmd
{
    enum bfc_object object;
    enum bfc_action action;
    const char *name;
    uint32_t valid_opts;
    uint32_t required_opts;
    const char *doc;
    int (*cb)(const struct bfc_opts *opts);
};

/**
 * @brief Initialize a `bfc_opts` object to default values.
 */
#define bfc_opts_default()                                                     \
    {.object = _BFC_OBJECT_MAX, .action = _BFC_ACTION_MAX};

void bfc_opts_clean(struct bfc_opts *opts);
int bfc_opts_parse(struct bfc_opts *opts, int argc, char **argv);
