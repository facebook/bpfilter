/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * @file ns.h
 *
 * `bpfilter` supports the following namespaces:
 * - **Network**: for interfaces index to attach XDP and TC programs to, and
 *   interface indexes to filter on.
 * - **Mount**: for CGroup path to attach `cgroup_skb` programs to.
 *
 * For each supported namespace, the `bf_ns` structure stores the namespace's
 * ID (the namespace file inode number), and a file descriptor to the namespace.
 *
 * When a request is received, `bpfilter` will create a new `bf_ns` object
 * to refer to the client's namespaces. Before calling
 * `bf_flavor_ops.attach_prog`, `bpfilter` will jump to the request's
 * namespace, attach the program, then jump back to the original namespace.
 */

struct bf_ns_info
{
    int fd;
    uint32_t inode;
};

/**
 * Contains information about namespaces relevant to bpfilter.
 */
struct bf_ns
{
    struct bf_ns_info net;
    struct bf_ns_info mnt;
};

/**
 * Call `bf_ns_clean` on an `auto` stored `bf_ns` when it goes out of scope to
 * avoid resources leakage.
 */
#define _clean_bf_ns_ __attribute__((cleanup(bf_ns_clean)))

/**
 * Initialize a new `bf_ns` to default values.
 *
 * Ensure an `auto` stored `bf_ns` are initialized to sane defaults, so
 * `bf_ns_clean()` can be called safely.
 *
 * @return An initialized `bf_ns` object.
 */
#define bf_ns_default()                                                        \
    (struct bf_ns)                                                             \
    {                                                                          \
        .net = {.fd = -1}, .mnt = {.fd = -1}                                   \
    }

/**
 * Move a `bf_ns` object.
 *
 * Move the `bf_ns` object from `ns` and return it. Once moved, `ns` will be
 * reset to default values (see `bf_ns_default()`) on which `bf_ns_clean()` can
 * safely be called. The caller is responsible for cleaning up the `bf_ns`
 * object returned.
 *
 * @param ns Variable to move the `bf_ns` object out of.
 * @return A `bf_ns` object.
 */
#define bf_ns_move(ns)                                                         \
    ({                                                                         \
        struct bf_ns *__ns = &(ns);                                            \
        struct bf_ns _ns = *__ns;                                              \
        *__ns = bf_ns_default();                                               \
        _ns;                                                                   \
    })

/**
 * Initialize an allocated `bf_ns` object.
 *
 * The `procfs` entry of `pid` will be used to open a reference to its
 * network and mount namespaces and store it in `ns`.
 *
 * @param ns Object to initialize. On failure, this parameter is unchanged.
 *        Can't be NULL.
 * @param pid PID of the process to open the namespaces of.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ns_init(struct bf_ns *ns, pid_t pid);

/**
 * Clean a `bf_ns` object.
 *
 * @param ns Object to clean. Can't be NULL.
 */
void bf_ns_clean(struct bf_ns *ns);

/**
 * Move the current process to different namespaces.
 *
 * This function will change the current namespace to the one defined in `ns`.
 * It is critical for this function to succeed; otherwise the process will be
 * in an unstable state: partially in a new namespace, partially in its original
 * namespace.
 *
 * @param ns Namespaces to move to. Can't be NULL.
 * @param oldns Namespaces to move out of. This information is needed as
 *        `setns()` will fail if we try to move to a namespace we are already in.
 *        It is not possible for `setns()` to look up the current namespace
 *        itself, as we must assume a new `/proc` has been mounted too,
 *        hiding the information about the current process. Hence, the only
 *        reliable solution is to collect this information before calling
 *        `setns()`.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ns_set(const struct bf_ns *ns, const struct bf_ns *oldns);
