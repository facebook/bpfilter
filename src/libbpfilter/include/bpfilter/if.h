/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>

/**
 * @file if.h
 *
 * Header files `net/if.h` and `arpa/inet.h` are incompatible with some kernel
 * headers, due to symbols being defined in both. However, the Linux kernel used
 * in `bpfilter` are mandatory, we can't do without them. In order to avoid
 * further issues due to this incompatibility, `net/if.h` and `arpa/inet/h` are
 * now hidden in `if.c`, and `bpfilter`-specific functions have been defined to
 * provide the required functionalities.
 */

/**
 * Get an interface index from its name.
 *
 * @param name Name of the interface. Can't be NULL.
 * @return Index of the interface. If the interface name is unknown, a
 *         negative errno value is returned.
 */
int bf_if_index_from_name(const char *name);

/**
 * Get an interface name from its index.
 *
 * This function copy the interface name into a static buffer, this would
 * probably be an issue for multi-threaded application, but thankfully bpfilter
 * is a single-threaded daemon.
 *
 * @param index Index of the interface.
 * @return Pointer to a static buffer containing the interface name, or NULL
 *         if the interface name is not found.
 */
const char *bf_if_name_from_index(int index);

/**
 * @brief Parse an interface identifier from a string.
 *
 * The string can be either an interface name (e.g., "eth0", "wlan0") or a
 * decimal interface index (e.g., "1", "2"). Interface names are resolved first;
 * if that fails, the string is parsed as a numeric index.
 *
 * @param str String to parse. Can't be NULL.
 * @param ifindex Pointer to store the interface index. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_if_index_from_str(const char *str, uint32_t *ifindex);
