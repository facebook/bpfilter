/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/logger.h"

#include <errno.h>
#include <string.h>

#include "fake.h"
#include "mock.h"
#include "test.h"

static void log_level_get_set(void **state)
{
    enum bf_log_level original_level;

    (void)state;

    // Save original level
    original_level = bf_log_get_level();

    // Test setting and getting each log level
    bf_log_set_level(BF_LOG_DBG);
    assert_int_equal(bf_log_get_level(), BF_LOG_DBG);

    bf_log_set_level(BF_LOG_INFO);
    assert_int_equal(bf_log_get_level(), BF_LOG_INFO);

    bf_log_set_level(BF_LOG_WARN);
    assert_int_equal(bf_log_get_level(), BF_LOG_WARN);

    bf_log_set_level(BF_LOG_ERR);
    assert_int_equal(bf_log_get_level(), BF_LOG_ERR);

    bf_log_set_level(BF_LOG_ABORT);
    assert_int_equal(bf_log_get_level(), BF_LOG_ABORT);

    // Restore original level
    bf_log_set_level(original_level);
}

static void log_level_to_str(void **state)
{
    (void)state;

    // Test all log level strings
    assert_non_null(bf_log_level_to_str(BF_LOG_DBG));
    assert_string_equal(bf_log_level_to_str(BF_LOG_DBG), "debug");

    assert_non_null(bf_log_level_to_str(BF_LOG_INFO));
    assert_string_equal(bf_log_level_to_str(BF_LOG_INFO), "info");

    assert_non_null(bf_log_level_to_str(BF_LOG_WARN));
    assert_string_equal(bf_log_level_to_str(BF_LOG_WARN), "warning");

    assert_non_null(bf_log_level_to_str(BF_LOG_ERR));
    assert_string_equal(bf_log_level_to_str(BF_LOG_ERR), "error");

    assert_non_null(bf_log_level_to_str(BF_LOG_ABORT));
    assert_string_equal(bf_log_level_to_str(BF_LOG_ABORT), "abort");
}

static void log_level_from_str(void **state)
{
    (void)state;

    // Test valid strings
    assert_int_equal(bf_log_level_from_str("debug"), BF_LOG_DBG);
    assert_int_equal(bf_log_level_from_str("info"), BF_LOG_INFO);
    assert_int_equal(bf_log_level_from_str("warning"), BF_LOG_WARN);
    assert_int_equal(bf_log_level_from_str("error"), BF_LOG_ERR);
    assert_int_equal(bf_log_level_from_str("abort"), BF_LOG_ABORT);

    // Test invalid strings - cast to int as enum doesn't preserve negative
    assert_true((int)bf_log_level_from_str("invalid") < 0);
    assert_true((int)bf_log_level_from_str("DEBUG") < 0);
    assert_true((int)bf_log_level_from_str("") < 0);
}

static void log_level_roundtrip(void **state)
{
    (void)state;

    // Test roundtrip conversion for all levels
    for (enum bf_log_level level = BF_LOG_DBG; level < _BF_LOG_MAX; ++level) {
        const char *str = bf_log_level_to_str(level);
        assert_non_null(str);
        assert_int_equal(bf_log_level_from_str(str), level);
    }
}

static void logger_get_color_no_tty(void **state)
{
    (void)state;

    // In test environment (not a TTY), colors should return empty strings
    // bf_logger_setup() sets _bf_can_print_color based on isatty()

    // Call setup - in test environment, stdout/stderr are typically not TTYs
    bf_logger_setup();

    // All colors should return empty string when not a TTY
    assert_string_equal(bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_BOLD),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLACK, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLACK, BF_STYLE_BOLD), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_RED, BF_STYLE_NORMAL), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_RED, BF_STYLE_BOLD), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_GREEN, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_GREEN, BF_STYLE_BOLD), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_BOLD),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLUE, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLUE, BF_STYLE_BOLD), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_MAGENTA, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_MAGENTA, BF_STYLE_BOLD),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD), "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_GRAY, BF_STYLE_NORMAL), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_GRAY, BF_STYLE_BOLD),
                        "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_DARK_GRAY, BF_STYLE_NORMAL), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_DARK_GRAY, BF_STYLE_BOLD),
                        "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_RED, BF_STYLE_NORMAL), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_RED, BF_STYLE_BOLD),
                        "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_NORMAL), "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_BOLD), "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_NORMAL), "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD), "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_BLUE, BF_STYLE_NORMAL), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_BLUE, BF_STYLE_BOLD),
                        "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_NORMAL), "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD), "");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_NORMAL), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_WHITE, BF_STYLE_NORMAL),
                        "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_WHITE, BF_STYLE_BOLD), "");
    assert_string_equal(bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                        "");
}

static void logger_get_color_values(void **state)
{
    (void)state;

    // Even when colors are disabled, the function should not crash
    // and should return valid (empty) strings for all color/style combinations

    bf_logger_setup();

    // Test all colors with normal style
    assert_non_null(bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_BLACK, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_RED, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_GREEN, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_BLUE, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_MAGENTA, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_GRAY, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_DARK_GRAY, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_RED, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_NORMAL));
    assert_non_null(
        bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_BLUE, BF_STYLE_NORMAL));
    assert_non_null(
        bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_NORMAL));
    assert_non_null(bf_logger_get_color(BF_COLOR_WHITE, BF_STYLE_NORMAL));

    // Test all colors with bold style
    assert_non_null(bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_BLACK, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_RED, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_GREEN, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_BLUE, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_MAGENTA, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_GRAY, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_DARK_GRAY, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_RED, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_BLUE, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD));
    assert_non_null(bf_logger_get_color(BF_COLOR_WHITE, BF_STYLE_BOLD));

    // Test reset
    assert_non_null(bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
}

static void logger_setup(void **state)
{
    (void)state;

    // Just verify setup doesn't crash
    bf_logger_setup();

    // After setup, get_color should work
    assert_non_null(bf_logger_get_color(BF_COLOR_RED, BF_STYLE_BOLD));
}

static void logger_get_color_with_tty(void **state)
{
    (void)state;

    // Mock isatty to return true (simulating a TTY)
    _clean_bft_mock_ bft_mock mock = bft_mock_get(isatty);
    (void)mock;

    // Setup logger with mocked TTY
    bf_logger_setup();

    // Now colors should return ANSI escape codes
    // Test all colors with normal style
    assert_string_equal(bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_NORMAL),
                        "\033[0;39m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_BOLD),
                        "\033[1;39m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLACK, BF_STYLE_NORMAL),
                        "\033[0;30m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLACK, BF_STYLE_BOLD),
                        "\033[1;30m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_RED, BF_STYLE_NORMAL),
                        "\033[0;31m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_RED, BF_STYLE_BOLD),
                        "\033[1;31m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_GREEN, BF_STYLE_NORMAL),
                        "\033[0;32m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_GREEN, BF_STYLE_BOLD),
                        "\033[1;32m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_NORMAL),
                        "\033[0;33m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_BOLD),
                        "\033[1;33m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLUE, BF_STYLE_NORMAL),
                        "\033[0;34m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_BLUE, BF_STYLE_BOLD),
                        "\033[1;34m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_MAGENTA, BF_STYLE_NORMAL),
                        "\033[0;35m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_MAGENTA, BF_STYLE_BOLD),
                        "\033[1;35m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_NORMAL),
                        "\033[0;36m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD),
                        "\033[1;36m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_GRAY, BF_STYLE_NORMAL),
        "\033[0;37m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_GRAY, BF_STYLE_BOLD),
                        "\033[1;37m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_DARK_GRAY, BF_STYLE_NORMAL), "\033[0;90m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_DARK_GRAY, BF_STYLE_BOLD),
                        "\033[1;90m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_RED, BF_STYLE_NORMAL), "\033[0;91m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_RED, BF_STYLE_BOLD),
                        "\033[1;91m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_NORMAL),
        "\033[0;92m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_BOLD), "\033[1;92m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_NORMAL),
        "\033[0;93m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
        "\033[1;93m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_BLUE, BF_STYLE_NORMAL),
        "\033[0;94m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_BLUE, BF_STYLE_BOLD),
                        "\033[1;94m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_NORMAL),
        "\033[0;95m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD),
        "\033[1;95m");
    assert_string_equal(
        bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_NORMAL),
        "\033[0;96m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD),
                        "\033[1;96m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_WHITE, BF_STYLE_NORMAL),
                        "\033[0;97m");
    assert_string_equal(bf_logger_get_color(BF_COLOR_WHITE, BF_STYLE_BOLD),
                        "\033[1;97m");

    // Test reset
    assert_string_equal(bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                        "\033[0m");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(log_level_get_set),
        cmocka_unit_test(log_level_to_str),
        cmocka_unit_test(log_level_from_str),
        cmocka_unit_test(log_level_roundtrip),
        cmocka_unit_test(logger_get_color_no_tty),
        cmocka_unit_test(logger_get_color_values),
        cmocka_unit_test(logger_setup),
        cmocka_unit_test(logger_get_color_with_tty),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
