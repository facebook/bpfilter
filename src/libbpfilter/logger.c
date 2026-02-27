/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/logger.h"

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

/// If true, log messages will be printed in colors.
static bool _bf_can_print_color = false;

/** Default log level for log messages. All the logs below this level will
 * be ignored (not printed). */
static enum bf_log_level _bf_log_level = BF_LOG_INFO;

void bf_logger_setup(void)
{
    _bf_can_print_color = isatty(fileno(stdout)) && isatty(fileno(stderr));
}

const char *bf_logger_get_color(enum bf_color color, enum bf_style style)
{
    if (!_bf_can_print_color) {
        return "";
    }

    switch (color) {
    case BF_COLOR_DEFAULT:
        return (style == BF_STYLE_BOLD) ? "\033[1;39m" : "\033[0;39m";
    case BF_COLOR_BLACK:
        return (style == BF_STYLE_BOLD) ? "\033[1;30m" : "\033[0;30m";
    case BF_COLOR_RED:
        return (style == BF_STYLE_BOLD) ? "\033[1;31m" : "\033[0;31m";
    case BF_COLOR_GREEN:
        return (style == BF_STYLE_BOLD) ? "\033[1;32m" : "\033[0;32m";
    case BF_COLOR_YELLOW:
        return (style == BF_STYLE_BOLD) ? "\033[1;33m" : "\033[0;33m";
    case BF_COLOR_BLUE:
        return (style == BF_STYLE_BOLD) ? "\033[1;34m" : "\033[0;34m";
    case BF_COLOR_MAGENTA:
        return (style == BF_STYLE_BOLD) ? "\033[1;35m" : "\033[0;35m";
    case BF_COLOR_CYAN:
        return (style == BF_STYLE_BOLD) ? "\033[1;36m" : "\033[0;36m";
    case BF_COLOR_LIGHT_GRAY:
        return (style == BF_STYLE_BOLD) ? "\033[1;37m" : "\033[0;37m";
    case BF_COLOR_DARK_GRAY:
        return (style == BF_STYLE_BOLD) ? "\033[1;90m" : "\033[0;90m";
    case BF_COLOR_LIGHT_RED:
        return (style == BF_STYLE_BOLD) ? "\033[1;91m" : "\033[0;91m";
    case BF_COLOR_LIGHT_GREEN:
        return (style == BF_STYLE_BOLD) ? "\033[1;92m" : "\033[0;92m";
    case BF_COLOR_LIGHT_YELLOW:
        return (style == BF_STYLE_BOLD) ? "\033[1;93m" : "\033[0;93m";
    case BF_COLOR_LIGHT_BLUE:
        return (style == BF_STYLE_BOLD) ? "\033[1;94m" : "\033[0;94m";
    case BF_COLOR_LIGHT_MAGENTA:
        return (style == BF_STYLE_BOLD) ? "\033[1;95m" : "\033[0;95m";
    case BF_COLOR_LIGHT_CYAN:
        return (style == BF_STYLE_BOLD) ? "\033[1;96m" : "\033[0;96m";
    case BF_COLOR_WHITE:
        return (style == BF_STYLE_BOLD) ? "\033[1;97m" : "\033[0;97m";
    default:
        return "\033[0m";
    }
}

enum bf_log_level bf_log_get_level(void)
{
    return _bf_log_level;
}

void bf_log_set_level(enum bf_log_level level)
{
    _bf_log_level = level;
}

static const char *_bf_log_level_strs[] = {
    [BF_LOG_DBG] = "debug", [BF_LOG_INFO] = "info",   [BF_LOG_WARN] = "warning",
    [BF_LOG_ERR] = "error", [BF_LOG_ABORT] = "abort",
};
static_assert_enum_mapping(_bf_log_level_strs, _BF_LOG_MAX);

const char *bf_log_level_to_str(enum bf_log_level level)
{
    return _bf_log_level_strs[level];
}

enum bf_log_level bf_log_level_from_str(const char *str)
{
    assert(str);

    for (enum bf_log_level level = 0; level < _BF_LOG_MAX; ++level) {
        if (bf_streq(_bf_log_level_strs[level], str))
            return level;
    }

    return -EINVAL;
}
