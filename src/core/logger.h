/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdio.h> // NOLINT: fprintf is used

#include "core/helper.h"
#include "core/opts.h" // NOLINT: bf_opts_verbose() is used

enum bf_color
{
    BF_COLOR_RESET = 0,

    BF_COLOR_DEFAULT = 1 << 1,
    BF_COLOR_BLACK = 1 << 2,
    BF_COLOR_RED = 1 << 3,
    BF_COLOR_GREEN = 1 << 4,
    BF_COLOR_YELLOW = 1 << 5,
    BF_COLOR_BLUE = 1 << 6,
    BF_COLOR_MAGENTA = 1 << 7,
    BF_COLOR_CYAN = 1 << 8,
    BF_COLOR_LIGHT_GRAY = 1 << 9,
    BF_COLOR_DARK_GRAY = 1 << 10,
    BF_COLOR_LIGHT_RED = 1 << 11,
    BF_COLOR_LIGHT_GREEN = 1 << 12,
    BF_COLOR_LIGHT_YELLOW = 1 << 13,
    BF_COLOR_LIGHT_BLUE = 1 << 14,
    BF_COLOR_LIGHT_MAGENTA = 1 << 15,
    BF_COLOR_LIGHT_CYAN = 1 << 16,
    BF_COLOR_WHITE = 1 << 17,
};

enum bf_style
{
    BF_STYLE_RESET = 0,

    // First bit is for the weight.
    BF_STYLE_NORMAL = 0,
    BF_STYLE_BOLD = 1,
};

/**
 * Log an error message to stderr.
 *
 * @param level Log level, as a string. Will prefix the log message.
 * @param color Color to print the prefix with, as a @ref bf_color .
 * @param fmt Format string.
 * @param ... Format arguments.
 */
#define _bf_log_impl(level, color, fmt, ...)                                   \
    (void)fprintf(stderr, "%s%-7s%s: " fmt "\n",                               \
                  bf_logger_get_color((color), BF_STYLE_BOLD), (level),        \
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),         \
                  ##__VA_ARGS__)

#define bf_abort(fmt, ...)                                                     \
    ({                                                                         \
        _bf_log_impl("abort", BF_COLOR_RED, fmt, ##__VA_ARGS__);               \
        abort();                                                               \
    })

#define bf_err(fmt, ...) _bf_log_impl("error", BF_COLOR_RED, fmt, ##__VA_ARGS__)

#define bf_warn(fmt, ...)                                                      \
    _bf_log_impl("warning", BF_COLOR_YELLOW, fmt, ##__VA_ARGS__)

#define bf_info(fmt, ...)                                                      \
    _bf_log_impl("info", BF_COLOR_GREEN, fmt, ##__VA_ARGS__)

#define bf_dbg(fmt, ...)                                                       \
    ({                                                                         \
        if (bf_opts_verbose())                                                 \
            _bf_log_impl("debug", BF_COLOR_BLUE, fmt, ##__VA_ARGS__);          \
    })

/**
 * Log an error message to stderr, append the detail of the error code
 * provided and return the given error code.
 *
 * Convenience function to be used during error checks. It will log the error
 * message to stderr, append the detail of the error code provided and return
 * the given error code as a negative value. For example:
 *
 * @code{.c}
 *  if (ret < 0)
 *    return bf_err_r(ret, "failed to do something");
 * @endcode
 *
 * @param level Log level, as a string. Will prefix the log message.
 * @param color Color to print the prefix with, as a @ref bf_color .
 * @param code Error code, can be positive or negative.
 * @param fmt Format string.
 * @param ... Format arguments.
 * @return The given error code, as a negative value.
 */
#define _bf_log_code_impl(level, color, code, fmt, ...)                        \
    ({                                                                         \
        fprintf(stderr, "%s%-7s%s: " fmt ": %s\n",                             \
                bf_logger_get_color((color), BF_STYLE_BOLD), (level),          \
                bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),           \
                ##__VA_ARGS__, bf_strerror(code));                             \
        -abs(code);                                                            \
    })

#define bf_err_r(code, fmt, ...)                                               \
    _bf_log_code_impl("error", BF_COLOR_RED, code, fmt, ##__VA_ARGS__)

#define bf_warn_r(code, fmt, ...)                                              \
    _bf_log_code_impl("warning", BF_COLOR_YELLOW, code, fmt, ##__VA_ARGS__)

#define bf_info_r(code, fmt, ...)                                              \
    _bf_log_code_impl("info", BF_COLOR_GREEN, code, fmt, ##__VA_ARGS__)

#define bf_dbg_r(code, fmt, ...)                                               \
    _bf_log_code_impl("debug", BF_COLOR_BLUE, code, fmt, ##__VA_ARGS__)

/**
 * Identical to @ref _bf_log_impl but for @p va_list arguments.
 *
 * @param level Log level, as a string. Will prefix the log message.
 * @param color Color to print the prefix with, as a @ref bf_color .
 * @param fmt Format string.
 * @param vargs @p va_list of arguments.
 */
#define _bf_log_v_impl(level, color, fmt, vargs)                               \
    do {                                                                       \
        (void)fprintf(                                                         \
            stderr, "%s%-7s%s: ", bf_logger_get_color((color), BF_STYLE_BOLD), \
            (level), bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));     \
        (void)vfprintf(stderr, (fmt), (vargs));                                \
        (void)fprintf(stderr, "\n");                                           \
    } while (0)

#define bf_err_v(fmt, vargs) _bf_log_v_impl("error", BF_COLOR_RED, fmt, vargs)

#define bf_warn_v(fmt, vargs)                                                  \
    _bf_log_v_impl("warning", BF_COLOR_YELLOW, fmt, vargs)

#define bf_info_v(fmt, vargs) _bf_log_v_impl("info", BF_COLOR_GREEN, fmt, vargs)

#define bf_dbg_v(fmt, vargs) _bf_log_v_impl("debug", BF_COLOR_BLUE, fmt, vargs)

/**
 * Initialise the logging system.
 *
 * Defines whether the logging system will print in colors or not. If both
 * `stdout` and `stderr` are TTYs, then @ref _bf_can_print_color is set to true.
 */
void bf_logger_setup(void);

/**
 * Get color string for a given style.
 *
 * @p style can be a combination of @ref bf_style weight and color. If
 * @ref _bf_can_print_color is set to false, then an empty string will be
 * returned so to not modify the output style.
 *
 * @param color Color identifier.
 * @param style Style identifier.
 * @return Style string.
 */
const char *bf_logger_get_color(enum bf_color color, enum bf_style style);
