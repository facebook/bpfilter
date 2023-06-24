/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <string.h>

/**
 * @brief Returns true if @p a is equal to @p b.
 *
 * @param a First string.
 * @param b Second string.
 * @return True if @p a == @p b, false otherwise.
 */
static bool streq(const char *a, const char *b)
{
    return strcmp(a, b) == 0;
}
