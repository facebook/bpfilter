/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

/**
 * @brief Dump prefixed-print helper.
 *
 * @param p Prefix string.
 * @param fmt Log format string.
 * @param ... Variadic argument list for @p fmt.
 */
#define DUMP_P(p, fmt, ...) \
        fprintf(stdout, "%s" fmt, p, ##__VA_ARGS__);

/**
 * @brief Split 32 bits IPv4 representation into four 8 bits components.
 *
 * @param addr 32 bits IPv4 address to split.
 */
#define IP4_SPLIT(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

/**
 * @brief Split a byte into 8 characters representing each bit.
 *
 * @param byte Byte to split.
 */
#define BIN_SPLIT(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')

/**
 * @brief Format to use with BIN_SPLIT() to print a byte as 8 bits.
 */
#define BIN_FMT "%c%c%c%c%c%c%c%c"

/**
 * @brief Maximum length of the prefix buffer.
 */
#define DUMP_PREFIX_LEN 65

/**
 * @brief Add a symbol to the prefix string.
 * @param prefix Prefix string.
 */
void bf_dump_prefix_push(char *prefix);

/**
 * @brief Convert previous node to make is the last of the branch.
 *
 * @param prefix Prefix string.
 * @return @p prefix
 */
char *bf_dump_prefix_last(char *prefix);

/**
 * @brief Remove rightmost branch from the prefix string.
 *
 * When a subtree is completed and we backout to a different branch, we need
 * to remove the rightmost branch from the prefix to continue.
 *
 * @param prefix Prefix string.
 */
void bf_dump_prefix_pop(char *prefix);
