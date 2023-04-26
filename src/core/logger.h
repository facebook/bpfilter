/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Return a string describing the given error code.
 *
 * @param v Error code, can be positive or negative.
 */
#define _strerror(v) strerror(abs(v))

/**
 * @brief Log an error message to stderr.
 *
 * @param fmt Format string.
 * @param ... Format arguments.
 */
#define _bf_log_impl(fmt, ...) ({ fprintf(stderr, fmt "\n", ##__VA_ARGS__); })

#define bf_err(fmt, ...) ({ _bf_log_impl("error: " fmt, ##__VA_ARGS__); })

#define bf_info(fmt, ...) ({ _bf_log_impl("info : " fmt, ##__VA_ARGS__); })

#ifndef NDEBUG
#define bf_dbg(fmt, ...) ({ _bf_log_impl("debug: " fmt, ##__VA_ARGS__); })
#else
#define bf_dbg(...)
#endif

/**
 * @brief Log an error message to stderr, append the detail of the error code
 *  provided and return the given error code.
 *
 * Convenience function to be used during error checks. It will log the error
 * message to stderr, append the detail of the error code provided and return
 * the given error code as a negative value. For example:
 *
 *  if (ret < 0)
 *    return bf_err_code(ret, "failed to do something");
 *
 * @param code Error code, can be positive or negative.
 * @param fmt Format string.
 * @param ... Format arguments.
 * @return The given error code, as a negative value.
 */
#define _bf_log_code_impl(code, fmt, ...)                                      \
    ({                                                                         \
        fprintf(stderr, fmt ": %s\n", ##__VA_ARGS__, _strerror(code));         \
        -abs(code);                                                            \
    })

#define bf_err_code(code, fmt, ...)                                            \
    ({ _bf_log_code_impl(code, "error: " fmt, ##__VA_ARGS__); })

#define bf_info_code(code, fmt, ...)                                           \
    ({ _bf_log_code_impl(code, "info : " fmt, ##__VA_ARGS__); })

#ifndef NDEBUG
#define bf_dbg_code(code, fmt, ...)                                            \
    ({ _bf_log_code_impl(code, "debug: " fmt, ##__VA_ARGS__); })
#else
#define bf_dbg_code(code, fmt, ...)
#endif
