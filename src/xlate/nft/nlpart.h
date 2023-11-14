/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/dump.h"

struct bf_nlpart;
struct nlmsghdr;
struct nlattr;
struct nla_policy;

typedef struct nlattr bf_nlattr;

#define _cleanup_bf_nlpart_ __attribute__((__cleanup__(bf_nlpart_free)))

#define bf_nlattr_data(attr) nla_data(attr)

/**
 * @brief Create a new Netlink part.
 *
 * @param part Pointer to the new part. Must not be NULL. Will be allocated
 * and initialised by this function. On error, @p part is left untouched.
 * @param family Netlink message family.
 * @param command Netlink message command.
 * @param flags Netlink message flags.
 * @param seqnr Message sequence number.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlpart_new(struct bf_nlpart **part, uint16_t family, uint16_t command,
                  uint16_t flags, uint16_t seqnr);

/**
 * @brief Create a new Netlink part from an existing Netlink message.
 *
 * @param part Pointer to the new part. Must not be NULL. Will be allocated
 * and initialised by this function. On error, @p part is left untouched.
 * @param nlh Netlink message to create the part from. Must not be NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlpart_new_from_nlmsghdr(struct bf_nlpart **part, struct nlmsghdr *nlh);

/**
 * @brief Free a Netlink part.
 *
 * @param part Part to free. If @p part is NULL, nothing is done.
 */
void bf_nlpart_free(struct bf_nlpart **part);

/**
 * @brief Get the Netlink part header.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Pointer to the Netlink part header.
 */
struct nlmsghdr *bf_nlpart_hdr(const struct bf_nlpart *part);

/**
 * @brief Get the Netlink part's payload.
 *
 * If the Netlink part doesn't contain any payload, NULL is returned.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Pointer to the payload, or NULL if the Netlink part is empty.
 */
void *bf_nlpart_data(const struct bf_nlpart *part);

/**
 * @brief Get the total usable size of the Netlink part.
 *
 * Netlink parts can be padded to 4-byte boundaries. This function returns the
 * total usable size of the Netlink part, excluding any padding.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Total usable size of the Netlink part.
 */
size_t bf_nlpart_size(const struct bf_nlpart *part);

/**
 * @brief Get the total size of the Netlink part, including padding.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Total size of the Netlink part, including padding.
 */
size_t bf_nlpart_padded_size(const struct bf_nlpart *part);

/**
 * @brief Get the Netlink message family from the Netlink part.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Netlink message family.
 */
int bf_nlpart_family(const struct bf_nlpart *part);

/**
 * @brief Get the Netlink message type from the Netlink part.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Netlink message type.
 */
int bf_nlpart_command(const struct bf_nlpart *part);

/**
 * @brief Get the Netlink message flags from the Netlink part.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Netlink message flags.
 */
int bf_nlpart_flags(const struct bf_nlpart *part);

/**
 * @brief Get the Netlink part sequence number.
 *
 * @param part Netlink part. Can't be NULL.
 * @return Netlink part sequence number.
 */
uint16_t bf_nlpart_seqnr(const struct bf_nlpart *part);

/**
 * @brief Get the first attribute of the Netlink part.
 *
 * @param part Netlink part. Can't be NULL.
 * @param extra_hdr_len Extra header length of the Netlink part.
 * @return Pointer to the first attribute of the Netlink part.
 */
struct nlattr *bf_nlpart_attr(const struct bf_nlpart *part,
                              size_t extra_hdr_len);

/**
 * @brief Get the total length of the Netlink part attributes.
 *
 * @param part Netlink part. Can't be NULL.
 * @param extra_hdr_len Extra header length of the Netlink part.
 * @return Total length of the Netlink part attributes.
 */
int bf_nlpart_attrlen(const struct bf_nlpart *part, size_t extra_hdr_len);

/**
 * @brief Parse the Netlink part attributes.
 *
 * @param part Netlink part to parse. Can't be NULL.
 * @param extra_hdr_len Expected extra header length of the Netlink part.
 * @param attrs Pointer to the Netlink attributes. Can't be NULL. The parsed
 * attributes will be stored here.
 * @param maxtype Maximum attribute type.
 * @param policy Attribute policy. Can be NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlpart_parse(const struct bf_nlpart *part, size_t extra_hdr_len,
                    bf_nlattr **attrs, int maxtype,
                    const struct nla_policy *policy);

int bf_nlpart_parse_nested(bf_nlattr *attr, bf_nlattr **attrs, int maxtype,
                           const struct nla_policy *policy);
/**
 * @brief Dump the Netlink part.
 *
 * @param part Netlink part to dump. Can't be NULL.
 * @param extra_hdr_len Extra header length of the Netlink part. Can be 0.
 * @param prefix Prefix to use for the dump. Can be NULL.
 */
void bf_nlpart_dump(const struct bf_nlpart *part, size_t extra_hdr_len,
                    prefix_t *prefix);

/**
 * @brief Add an extra header to the Netlink part.
 *
 * @param part Part to add the extra header to. Can't be NULL.
 * @param data Extra header data. Can't be NULL.
 * @param size Extra header size.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlpart_put_extra_header(struct bf_nlpart *part, void *data, size_t size);

/**
 * @brief Add an attribute to the Netlink part.
 *
 * @param part Part to add the attribute to. Can't be NULL.
 * @param attr Attribute type.
 * @param data Attribute data. Can't be NULL.
 * @param size Attribute size.
 * @return 0 on success, negative errno value on error.
 */
int bf_nlpart_put_attr(struct bf_nlpart *part, uint16_t attr, const void *data,
                       size_t size);

#define bf_nlpart_put_str(part, attr, value)                                   \
    bf_nlpart_put_attr(part, attr, value, strlen(value) + 1)
#define bf_nlpart_put_str_or_jmp(part, attr, value)                            \
    ({                                                                         \
        if (bf_nlpart_put_str(part, attr, value) < 0)                          \
            goto bf_nlpart_put_failure;                                        \
    })

#define bf_nlpart_put_u8(part, attr, value)                                    \
    bf_nlpart_put_attr(part, attr, (&(uint8_t) {value}), sizeof(uint8_t))
#define bf_nlpart_put_u8_or_jmp(part, attr, value)                             \
    ({                                                                         \
        if (bf_nlpart_put_u8(part, attr, value) < 0)                           \
            goto bf_nlpart_put_failure;                                        \
    })

#define bf_nlpart_put_u16(part, attr, value)                                   \
    bf_nlpart_put_attr(part, attr, (&(uint16_t) {value}), sizeof(uint16_t))
#define bf_nlpart_put_u16_or_jmp(part, attr, value)                            \
    ({                                                                         \
        if (bf_nlpart_put_u16(part, attr, value) < 0)                          \
            goto bf_nlpart_put_failure;                                        \
    })

#define bf_nlpart_put_u32(part, attr, value)                                   \
    bf_nlpart_put_attr(part, attr, (&(uint32_t) {value}), sizeof(uint32_t))
#define bf_nlpart_put_u32_or_jmp(part, attr, value)                            \
    ({                                                                         \
        if (bf_nlpart_put_u32(part, attr, value) < 0)                          \
            goto bf_nlpart_put_failure;                                        \
    })

#define bf_nlpart_put_u64(part, attr, value)                                   \
    bf_nlpart_put_attr(part, attr, (&(uint64_t) {value}), sizeof(uint64_t))
#define bf_nlpart_put_u64_or_jmp(part, attr, value)                            \
    ({                                                                         \
        if (bf_nlpart_put_u64(part, attr, value) < 0)                          \
            goto bf_nlpart_put_failure;                                        \
    })
