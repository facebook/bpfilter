#include <argp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/chain.h"
#include "core/list.h"
#include "core/dump.h"
#include "parser/lexer.h"
#include "parser/parser.h"

static struct bf_options
{
    const char *input_file;
} _opts = {
    .input_file = NULL,
};

static struct argp_option options[] = {
    {"file", 'f', "INPUT_FILE", 0, "Input file to use a rules source", 0},
    {0},
};

static error_t _bf_opts_parser(int key, char *arg, struct argp_state *state)
{
    UNUSED(arg);

    struct bf_options *opts = state->input;

    switch (key) {
    case 'f':
        opts->input_file = strdup(arg);
        if (!opts->input_file) {
            fprintf(stderr, "failed to allocate memory for '%s'\n", arg);
            return -ENOMEM;
        }
        break;
    case ARGP_KEY_END:
        if (!opts->input_file) {
            fprintf(stderr, "--file is required\n");
            return -EINVAL;
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct argp argp = {options, _bf_opts_parser, NULL, NULL, 0, NULL, NULL};
    bf_list chains = bf_list_default({.free = (bf_list_ops_free)bf_chain_free});
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &_opts);
    if (r) {
        fprintf(stderr, "failed to parse arguments\n");
        return EXIT_FAILURE;
    }

    printf("Using source file: %s\n", _opts.input_file);

    FILE *rules = fopen(_opts.input_file, "r");
    if (!rules) {
        fprintf(stderr, "Failed to read rules from 'rule.bpfilter'\n");
        return -1;
    }

    yyin = rules;

    r = yyparse(&chains);
    if (r == 1) {
        fprintf(stderr, "failed to parse rules, syntax invalid\n");
        return EXIT_FAILURE;
    } else if (r == 2) {
        fprintf(stderr, "failed to parse rules, not enough memory\n");
        return EXIT_FAILURE;
    }

    bf_list_foreach (&chains, chain_node)
        bf_chain_dump(bf_list_node_get_data(chain_node), EMPTY_PREFIX);

    fclose(rules);

    return 0;
}

void yyerror(bf_list *chains, const char *fmt, ...)
{
    UNUSED(chains);

    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(-1);
}
