/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

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
