/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "core/bpf_types.h"
#include "core/dump.h"
#include "core/flavor.h"
#include "core/list.h"

/**
 * @file hook.h
 *
 * bpfilter's BPF programs are attached to hooks in the kernel. While hooks
 * represent single attach points in the kernel, metadata are required to
 * customize the exact location or runtime behaviour of the BPF program.
 *
 * `bf_hook` enumeration values represent the attachment points located in the
 * kernel, `bf_hookopts` is used to define the metadata required to attach
 * a program to a given hook. A chain must be created for a given hook, as
 * the program type won't be enough, but the `bf_hookopts` information is
 * only required when the chain is attached to the hook.
 */

struct bf_marsh;

enum bf_hook
{
    BF_HOOK_XDP,
    BF_HOOK_TC_INGRESS,
    BF_HOOK_NF_PRE_ROUTING,
    BF_HOOK_NF_LOCAL_IN,
    BF_HOOK_NF_FORWARD,
    BF_HOOK_CGROUP_INGRESS,
    BF_HOOK_CGROUP_EGRESS,
    BF_HOOK_NF_LOCAL_OUT,
    BF_HOOK_NF_POST_ROUTING,
    BF_HOOK_TC_EGRESS,
    _BF_HOOK_MAX,
};

/**
 * @brief Netfilter hooks identifiers.
 *
 * This enumeration is a direct copy of `nf_inet_hooks`. `nf_inet_hooks` is part
 * of the kernel public API, so it should never be out of sync with the kernel
 * source. Additionally, `linux/netfilter.h` can't be included in public headers
 * as it would prevent bpfilter from building without compiler extensions.
 */
enum bf_nf_inet_hooks
{
    BF_NF_INET_PRE_ROUTING,
    BF_NF_INET_LOCAL_IN,
    BF_NF_INET_FORWARD,
    BF_NF_INET_LOCAL_OUT,
    BF_NF_INET_POST_ROUTING,
    BF_NF_INET_NUMHOOKS,
    BF_NF_INET_INGRESS = BF_NF_INET_NUMHOOKS,
};

/**
 * Convert a `bf_hook` value to a string.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return String representation of the hook.
 */
const char *bf_hook_to_str(enum bf_hook hook);

/**
 * Convert a string to a `bf_hook` value.
 *
 * @param str String to convert to a `bf_hook` value. Can't be NULL.
 * @return A valid `bf_hook` value on success, or a negative errno value
 *         on error.
 */
enum bf_hook bf_hook_from_str(const char *str);

/**
 * Convert a `bf_hook` value to a `bf_flavor` value.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return The `bf_flavor` value corresponding to `hook`.
 */
enum bf_flavor bf_hook_to_flavor(enum bf_hook hook);

/**
 * Convert a `bf_hook` value to a BPF program type.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return The BPF program type corresponding to `hook`.
 */
enum bf_bpf_prog_type bf_hook_to_bpf_prog_type(enum bf_hook hook);

/**
 * Convert a `bf_hook` value to a BPF attach type.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return The BPF attach type corresponding to `hook`.
 */
enum bf_bpf_attach_type bf_hook_to_bpf_attach_type(enum bf_hook hook);

/**
 * Convert a `bf_hook` value to a `bf_nf_inet_hooks` value.
 *
 * @param hook The hook to convert. Must be a valid Netfilter hook.
 * @return The `bf_nf_inet_hooks` corresponding to `hook`.
 */
enum bf_nf_inet_hooks bf_hook_to_nf_hook(enum bf_hook hook);

/**
 * Convert a `bf_nf_inet_hooks` value to a `bf_hook` value.
 *
 * @param hook The hook to convert. Must be a valid `bf_nf_inet_hooks` hook.
 * @return The corresponding `bf_hook` value.
 */
enum bf_hook bf_hook_from_nf_hook(enum bf_nf_inet_hooks hook);

/**
 * Convert a `bf_nf_inet_hooks` value to a string.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return String representation of the hook.
 */
const char *bf_nf_hook_to_str(enum bf_nf_inet_hooks hook);

struct bf_hookopts
{
    // Options
    uint32_t used_opts;

    // XDP and TC
    int ifindex;

    // cgroup
    const char *cgpath;

    // Netfilter
    unsigned int family;
    int priorities[2];
};

enum bf_hookopts_type
{
    BF_HOOKOPTS_IFINDEX,
    BF_HOOKOPTS_CGPATH,
    BF_HOOKOPTS_FAMILY,
    BF_HOOKOPTS_PRIORITIES,
    _BF_HOOKOPTS_MAX,
};

#define _clean_bf_hookopts_ __attribute__((cleanup(bf_hookopts_clean)))
#define _free_bf_hookopts_ __attribute__((cleanup(bf_hookopts_free)))

/**
 * Allocate and initialize a `bf_hookopts` object.
 *
 * @param hookopts `bf_hookopts` object to allocate and initialize. On failure,
 *        this parameter is unchanged. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hookopts_new(struct bf_hookopts **hookopts);

/**
 * Allocate and initialize a new `bf_hookopts` object from serialized data.
 *
 * @param hookopts `bf_hookopts` object to allocate and initialize from `marsh`.
 *        On failure, this parameter is unchanged. Can't be NULL.
 * @param marsh Serialized data to read a `bf_hookopts` from. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hookopts_new_from_marsh(struct bf_hookopts **hookopts,
                               const struct bf_marsh *marsh);

/**
 * @brief Cleanup a `bf_hookopts` object.
 *
 * Release the allocated memory *in* the object, but not the object itself.
 *
 * @param hookopts `bf_hookopts` object to cleanup. Can't be NULL.
 */
void bf_hookopts_clean(struct bf_hookopts *hookopts);

/**
 * Deallocate a `bf_hookopts` object.
 *
 * @param hookopts `bf_hookopts` object to cleanup and deallocate. If `*hookopts`
 *        is NULL, this function has no effect. Can't be NULL.
 */
void bf_hookopts_free(struct bf_hookopts **hookopts);

/**
 * Serialize a `bf_hookopts` object.
 *
 * @param hookopts `bf_hookopts` object to serialize. Can't be NULL.
 * @param marsh On success, represents the serialized `bf_hookopts` object. On
 *        failure, this parameter is unchanged. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hookopts_marsh(const struct bf_hookopts *hookopts,
                      struct bf_marsh **marsh);

/**
 * Dump the content of a `bf_hookopts` object.
 *
 * @param hookopts `bf_hookopts` object to print. Can't be NULL.
 * @param prefix Prefix to use for the dump. Can't be NULL.
 */
void bf_hookopts_dump(const struct bf_hookopts *hookopts, prefix_t *prefix);

/**
 * Parse a raw `bf_hookopts` option.
 *
 * `raw_opt` is expected to be formatted as `$NAME=$VALUE`.
 *
 * @param hookopts `bf_hookopts` object to write the option into once parsed.
 *        Can't be NULL.
 * @param raw_opt Raw option to read and parse. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hookopts_parse_opt(struct bf_hookopts *hookopts, const char *raw_opt);

/**
 * Parse a list of raw `bf_hookopts` options.
 *
 * See `bf_hookopts_parse_opt()` for more details.
 *
 * @param hookopts `bf_hookopts` object to write the option into once parsed.
 *        Can't be NULL.
 * @param raw_opts List of raw options to parse. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hookopts_parse_opts(struct bf_hookopts *hookopts, bf_list *raw_opts);

/**
 * Validate a `bf_hookopts` structure.
 *
 * Ensure `hookopts` contains all the options required by `hook`, and doesn't
 * contain unsupported options.
 *
 * @param hookopts `bf_hookopts` object to validate. Can't be NULL.
 * @param hook Hook to validate the options for.
 * @return 0 if the hook options are valid, or a negative errno value otherwise.
 */
int bf_hookopts_validate(const struct bf_hookopts *hookopts, enum bf_hook hook);

/**
 * Check if a specific hook option is used.
 *
 * @param hookopts Pointer to the `bf_hookopts` structure. Can't be NULL.
 * @param type Hook option type to test for.
 * @return True if the option is used, false otherwise.
 */
#define bf_hookopts_is_used(hookopts, type)                                    \
    ((hookopts)->used_opts & BF_FLAG(type))
