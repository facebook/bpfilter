/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/if.h>

#include <stddef.h>

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
 * Local interface details.
 */
struct bf_if_iface
{
    /// Index of the interface on the system.
    unsigned int index;
    /// Name of the interface.
    char name[IFNAMSIZ];
};

/**
 * Get an interface index from its name.
 *
 * @param name Name of the interface. Can't be NULL.
 * @return Index of the interface. If the interface name is unknown, a
 * negative errno value is returned.
 */
int bf_if_index_from_name(const char *name);

/**
 * Get an interface name from its index.
 *
 * If the interface index is invalid, or not found, @p buf is filled with
 * "<unknown>".
 *
 * This function copy the interface name into a static buffer, this would
 * probably be an issue for multi-threaded application, but thankfully bpfilter
 * is a single-threaded daemon.
 *
 * @param index Index of the interface.
 * @return Pointer to a static buffer containing the interface name.
 */
const char *bf_if_name_from_index(int index);

/**
 * Get the index and name of all the interfaces on the host.
 *
 * @param ifaces Array of @ref bf_if_iface structures. The array will be
 * allocated by the function and the caller is responsible for freeing it.
 * @return On success, return the number of interfaces contained in @p ifaces .
 * On failure, return a negative errno value.
 */
ssize_t bf_if_get_ifaces(struct bf_if_iface **ifaces);
