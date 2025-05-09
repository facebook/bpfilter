/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/opts.h"

#include <argp.h>

#include "bfcli/chain.h"
#include "bfcli/ruleset.h"
#include "core/helper.h"

/**
 * @brief Create a section header in the documentation.
 *
 * By creating an `argp_option` with no name or key, argph will print the option
 * as a section header.
 *
 * @param object Object type to create a section for.
 */
#define BFC_HELP_SECTION(object)                                               \
    {.group = (int)(object) + 1, .doc = _bfc_object_strs[object]}

/**
 * @brief Create a entry in the previous documentation section.
 *
 * @param action Action to create an entry for.
 * @param help Documentation for that entry.
 */
#define BFC_HELP_ENTRY(action, help)                                           \
    {.name = _bfc_action_strs[action], .doc = (help), .flags = OPTION_DOC}

static const char * const _bfc_object_strs[] = {
    "ruleset", // BFC_OBJECT_RULESET
    "chain", // BFC_OBJECT_CHAIN
};
static_assert(ARRAY_SIZE(_bfc_object_strs) == _BFC_OBJECT_MAX,
              "missing entries in bfc_object strings array");

static const char *bfc_object_to_str(enum bfc_object object)
{
    return _bfc_object_strs[object];
}

enum bfc_object bfc_object_from_str(const char *str)
{
    bf_assert(str);

    for (enum bfc_object object = 0; object < _BFC_OBJECT_MAX; ++object) {
        if (bf_streq(_bfc_object_strs[object], str))
            return object;
    }

    return -EINVAL;
}

static const char * const _bfc_action_strs[] = {
    "set", // BFC_ACTION_SET
    "get", // BFC_ACTION_GET
    "load", // BFC_ACTION_LOAD
    "attach", //BFC_ACTION_ATTACH
    "update", // BFC_ACTION_UPDATE
    "flush", // BFC_ACTION_FLUSH
};
static_assert(ARRAY_SIZE(_bfc_action_strs) == _BFC_ACTION_MAX,
              "missing entries in bfc_action strings array");

static const char *bfc_action_to_str(enum bfc_action action)
{
    return _bfc_action_strs[action];
}

enum bfc_action bfc_action_from_str(const char *str)
{
    bf_assert(str);

    for (enum bfc_action action = 0; action < _BFC_ACTION_MAX; ++action) {
        if (bf_streq(_bfc_action_strs[action], str))
            return action;
    }

    return -EINVAL;
}

enum bfc_opts_option_id
{
    BFC_OPT_RULESET_FROM_STR,
    BFC_OPT_RULESET_FROM_FILE,
    BFC_OPT_CHAIN_FROM_STR,
    BFC_OPT_CHAIN_FROM_FILE,
    BFC_OPT_CHAIN_NAME,
    BFC_OPT_CHAIN_HOOK_OPTS,
    _BFC_OPT_MAX,
};

static const struct bfc_opts_cmd _bfc_opts_cmds[] = {
    {
        .name = "bfcli ruleset set",
        .object = BFC_OBJECT_RULESET,
        .action = BFC_ACTION_SET,
        .valid_opts =
            BF_FLAGS(BFC_OPT_RULESET_FROM_STR, BFC_OPT_RULESET_FROM_FILE),
        .doc =
            "Set the ruleset.\vRemove all the chains on the system and "
            "replaced them with the one provided in --from-file or --from-str.",
        .cb = bfc_ruleset_set,
    },
    {
        .name = "bfcli ruleset get",
        .object = BFC_OBJECT_RULESET,
        .action = BFC_ACTION_GET,
        .doc = "Print the ruleset.\vPrint the current ruleset.",
        .cb = bfc_ruleset_get,
    },
    {
        .name = "bfcli ruleset flush",
        .object = BFC_OBJECT_RULESET,
        .action = BFC_ACTION_FLUSH,
        .doc = "Delete the ruleset.\vRemove every chain from the system.",
        .cb = bfc_ruleset_flush,
    },
    {
        .name = "bfcli chain set",
        .object = BFC_OBJECT_CHAIN,
        .action = BFC_ACTION_SET,
        .valid_opts = BF_FLAGS(BFC_OPT_CHAIN_FROM_STR, BFC_OPT_CHAIN_FROM_FILE,
                               BFC_OPT_CHAIN_NAME),
        .doc =
            "Set a new chain\vCreate a new chain, attach it if hook options "
            "are defined. Any existing chain with the same --name will be "
            "replaced. If --from-str or --from-file contains multiple chains, "
            "--name is used to select the right one.",
        .cb = bfc_chain_set,
    },
    {
        .name = "bfcli chain get",
        .object = BFC_OBJECT_CHAIN,
        .action = BFC_ACTION_GET,
        .valid_opts = BF_FLAGS(BFC_OPT_CHAIN_NAME),
        .doc =
            "Print an existing chain\vRequest the chain --name from the daemon "
            "and print it.",
        .cb = bfc_chain_get,
    },
    {
        .name = "bfcli chain load",
        .object = BFC_OBJECT_CHAIN,
        .action = BFC_ACTION_LOAD,
        .valid_opts = BF_FLAGS(BFC_OPT_CHAIN_FROM_STR, BFC_OPT_CHAIN_FROM_FILE,
                               BFC_OPT_CHAIN_NAME),
        .doc =
            "Load a new chain\vCreate a new chain, and load it into the "
            "kernel. An error will be returned if any existing chain has the "
            "same name. If --from-str or --from-file contains multiple chains, "
            "--name is used to select the right one.",
        .cb = bfc_chain_load,
    },
    {
        .name = "bfcli chain attach",
        .object = BFC_OBJECT_CHAIN,
        .action = BFC_ACTION_ATTACH,
        .valid_opts = BF_FLAGS(BFC_OPT_CHAIN_HOOK_OPTS, BFC_OPT_CHAIN_NAME),
        .doc =
            "Attach an existing chain\vAttach a loaded chain to a hook. Hook "
            "options defined with --option are specific to the chain and the "
            "hook to attach to.",
        .cb = bfc_chain_attach,
    },
    {
        .name = "bfcli chain update",
        .object = BFC_OBJECT_CHAIN,
        .action = BFC_ACTION_UPDATE,
        .valid_opts = BF_FLAGS(BFC_OPT_CHAIN_FROM_STR, BFC_OPT_CHAIN_FROM_FILE,
                               BFC_OPT_CHAIN_NAME),
        .doc = "Update a chain\vAtomically update chain --name with the new "
               "definition provided by --from-str or --from-file.",
        .cb = bfc_chain_update,
    },
    {
        .name = "bfcli chain flush",
        .object = BFC_OBJECT_CHAIN,
        .action = BFC_ACTION_FLUSH,
        .valid_opts = BF_FLAGS(BFC_OPT_CHAIN_NAME),
        .doc = "Delete a chain\vRemove a chain from the system.",
        .cb = bfc_chain_flush,
    },
};

const struct bfc_opts_cmd *_bfc_opts_get_cmd(enum bfc_object object,
                                             enum bfc_action action)
{
    for (size_t i = 0; i < ARRAY_SIZE(_bfc_opts_cmds); ++i) {
        if (_bfc_opts_cmds[i].object == object &&
            _bfc_opts_cmds[i].action == action)
            return &_bfc_opts_cmds[i];
    }

    return NULL;
}

static error_t _bfc_opts_parser(int key, char *arg, struct argp_state *state)
{
    struct bfc_opts *opts = state->input;

    switch (key) {
    case ARGP_KEY_ARG:
        if (state->arg_num == 0) {
            opts->object = bfc_object_from_str(arg);
            if ((int)opts->object < 0)
                argp_error(state, "unknown object '%s'", arg);
        } else if (state->arg_num == 1) {
            opts->action = bfc_action_from_str(arg);
            if ((int)opts->action < 0)
                argp_error(state, "unknown action '%s'", arg);
            opts->cmd = _bfc_opts_get_cmd(opts->object, opts->action);
            if (!opts->cmd)
                argp_error(state, "object '%s' does not support action '%s'",
                           bfc_object_to_str(opts->object),
                           bfc_action_to_str(opts->action));
            state->next = state->argc;
        } else {
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case ARGP_KEY_END:
        if (opts->object == _BFC_OBJECT_MAX || opts->action == _BFC_ACTION_MAX)
            argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static void _bfc_opts_from_str_cb(struct argp_state *state, const char *arg,
                                  struct bfc_opts *opts)
{
    if (opts->from_file)
        argp_error(state, "--from-str is incompatible with --from-file");

    opts->from_str = arg;
};

static void _bfc_opts_from_file_cb(struct argp_state *state, const char *arg,
                                   struct bfc_opts *opts)
{
    if (opts->from_str)
        argp_error(state, "--from-file is incompatible with --from-str");

    opts->from_file = arg;
};

static void _bfc_opts_chain_name_cb(struct argp_state *state, const char *arg,
                                    struct bfc_opts *opts)
{
    if (strlen(arg) == 0)
        argp_error(state, "--name can't be empty");

    opts->name = arg;
};

static void _bfc_opts_chain_hook_opts_cb(struct argp_state *state,
                                         const char *arg, struct bfc_opts *opts)
{
    if (bf_hookopts_parse_opt(&opts->hookopts, arg))
        argp_error(state, "failed to parse hook option '%s'", arg);
};

struct bfc_opts_opt
{
    enum bfc_opts_option_id id;
    int key;
    const char *name;
    const char *arg;
    const char *doc;
    void (*parser)(struct argp_state *state, const char *arg,
                   struct bfc_opts *opts);
} _bfc_options[] = {
    {
        .id = BFC_OPT_RULESET_FROM_STR,
        .key = 's',
        .name = "from-str",
        .arg = "STR",
        .doc = "String defining the ruleset",
        .parser = _bfc_opts_from_str_cb,
    },
    {
        .id = BFC_OPT_RULESET_FROM_FILE,
        .key = 'f',
        .name = "from-file",
        .arg = "FILE",
        .doc = "File defining the ruleset",
        .parser = _bfc_opts_from_file_cb,
    },
    {
        .id = BFC_OPT_CHAIN_FROM_STR,
        .key = 's',
        .name = "from-str",
        .arg = "STRING",
        .doc = "String defining the chain",
        .parser = _bfc_opts_from_str_cb,
    },
    {
        .id = BFC_OPT_CHAIN_FROM_FILE,
        .key = 'f',
        .name = "from-file",
        .arg = "FILE",
        .doc = "File defining the chain",
        .parser = _bfc_opts_from_file_cb,
    },
    {
        .id = BFC_OPT_CHAIN_NAME,
        .key = 'n',
        .name = "name",
        .arg = "NAME",
        .doc = "Name of the chain",
        .parser = _bfc_opts_chain_name_cb,
    },
    {
        .id = BFC_OPT_CHAIN_HOOK_OPTS,
        .key = 'o',
        .name = "option",
        .arg = "HOOKOPT=VALUE",
        .doc = "Hook option to attach the chain",
        .parser = _bfc_opts_chain_hook_opts_cb,
    },
};

static error_t _bfc_opts_cmd_parser(int key, char *arg,
                                    struct argp_state *state)
{
    struct bfc_opts *opts = state->input;
    const struct bfc_opts_cmd *cmd = opts->cmd;

    for (int i = 0; i < _BFC_OPT_MAX; ++i) {
        struct bfc_opts_opt *opt = &_bfc_options[i];

        if (!(cmd->valid_opts & BF_FLAG(i)) || key != opt->key)
            continue;

        opt->parser(state, arg, opts);

        return 0;
    }

    return ARGP_ERR_UNKNOWN;
}

void bfc_opts_clean(struct bfc_opts *opts)
{
    bf_assert(opts);

    bf_hookopts_clean(&opts->hookopts);
}

#define _BFC_NAME_LEN 32
static char _bfc_name[_BFC_NAME_LEN] = {};

int bfc_opts_parse(struct bfc_opts *opts, int argc, char **argv)
{
    static const struct argp_option options[] = {
        BFC_HELP_SECTION(BFC_OBJECT_RULESET),
        BFC_HELP_ENTRY(BFC_ACTION_SET,
                       "Set the current ruleset, replace any existing rule"),
        BFC_HELP_ENTRY(BFC_ACTION_GET, "Print the current ruleset"),
        BFC_HELP_ENTRY(BFC_ACTION_FLUSH, "Flush (drop) the current ruleset"),
        BFC_HELP_SECTION(BFC_OBJECT_CHAIN),
        BFC_HELP_ENTRY(
            BFC_ACTION_SET,
            "Set a new chain, replace any existing chain with the same name, attach if required"),
        BFC_HELP_ENTRY(BFC_ACTION_GET, "Print an existing chain"),
        BFC_HELP_ENTRY(BFC_ACTION_LOAD, "Load a new chain, do not attach it"),
        BFC_HELP_ENTRY(BFC_ACTION_ATTACH, "Attach a loaded chain"),
        BFC_HELP_ENTRY(BFC_ACTION_FLUSH, "Remove a chain"),
        {0},
    };
    static const struct argp parser = {
        .options = options,
        .parser = _bfc_opts_parser,
        .args_doc = "OBJECT ACTION",
        .doc =
            "Configure bpfilter chains and filtering rules.\v"
            "Examples:\n"
            "  # Set a ruleset from file\n"
            "  bfcli ruleset set --from-file myruleset.txt\n\n"
            "  # Create an XDP chain\n"
            "  bfcli chain set --from-str \"chain my_xdp_chain BF_HOOK_XDP ACCEPT rule ip4.saddr in {192.168.1.1} ACCEPT\"\n\n"
            "  # Get current ruleset\n"
            "  bfcli ruleset get\n\n"
            "  # Flush all rules\n"
            "  bfcli ruleset flush\n",
    };
    struct argp_option suboptions[_BFC_OPT_MAX + 1] = {};
    struct argp subparser = {.parser = _bfc_opts_cmd_parser};
    int suboptions_idx = 0;
    int r;

    r = argp_parse(&parser, argc, argv, ARGP_IN_ORDER, NULL, opts);
    if (r)
        return r;

    for (int i = 0; i < _BFC_OPT_MAX; ++i) {
        if (opts->cmd->valid_opts & BF_FLAG(i)) {
            suboptions[suboptions_idx++] = (struct argp_option) {
                .name = _bfc_options[i].name,
                .key = _bfc_options[i].key,
                .arg = _bfc_options[i].arg,
                .doc = _bfc_options[i].doc,
            };
        }
    }

    subparser.options = !opts->cmd->valid_opts ? NULL : suboptions;
    subparser.doc = opts->cmd->doc;

    (void)snprintf(_bfc_name, _BFC_NAME_LEN, "%s %s %s", argv[0],
                   bfc_object_to_str(opts->object),
                   bfc_action_to_str(opts->action));
    argv[2] = _bfc_name;
    argc -= 2;
    argv += 2;

    r = argp_parse(&subparser, argc, argv, 0, NULL, opts);

    return r;
}
