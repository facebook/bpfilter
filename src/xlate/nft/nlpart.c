/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nlpart.h"

#include <linux/netfilter/nf_tables.h>

#include <errno.h>
#include <netlink/msg.h>

#include "shared/helper.h"

#define BF_NLPART_FAMILY_MASK 0xff

struct bf_nlpart
{
    struct nl_msg *msg;
};

int bf_nlpart_new(struct bf_nlpart **part, uint16_t family, uint16_t command,
                  uint16_t flags, uint16_t seqnr)
{
    bf_assert(part);

    _cleanup_bf_nlpart_ struct bf_nlpart *_part = NULL;
    struct nlmsghdr *nlh;

    _part = calloc(1, sizeof(*_part));
    if (!_part)
        return -ENOMEM;

    _part->msg = nlmsg_alloc();
    if (!_part->msg)
        return -ENOMEM;

    nlh = nlmsg_put(_part->msg, 0, seqnr, family << 8 | command, 0, flags);
    if (!nlh)
        return -ENOMEM;

    *part = TAKE_PTR(_part);

    return 0;
}

int bf_nlpart_new_from_nlmsghdr(struct bf_nlpart **part, struct nlmsghdr *nlh)
{
    bf_assert(part);
    bf_assert(nlh);

    _cleanup_bf_nlpart_ struct bf_nlpart *_part = NULL;

    _part = calloc(1, sizeof(*_part));
    if (!_part)
        return -ENOMEM;

    _part->msg = nlmsg_convert(nlh);
    if (!_part->msg)
        return -ENOMEM;

    *part = TAKE_PTR(_part);

    return 0;
}

void bf_nlpart_free(struct bf_nlpart **part)
{
    bf_assert(part);

    if (!*part)
        return;

    nlmsg_free((*part)->msg);
    free(*part);
    *part = NULL;
}

struct nlmsghdr *bf_nlpart_hdr(const struct bf_nlpart *part)
{
    bf_assert(part);

    return nlmsg_hdr(part->msg);
}

void *bf_nlpart_data(const struct bf_nlpart *part)
{
    bf_assert(part);

    return nlmsg_datalen(bf_nlpart_hdr(part)) ?
               nlmsg_data(bf_nlpart_hdr(part)) :
               NULL;
}

size_t bf_nlpart_size(const struct bf_nlpart *part)
{
    bf_assert(part);

    return nlmsg_size(nlmsg_datalen(bf_nlpart_hdr(part)));
}

size_t bf_nlpart_padded_size(const struct bf_nlpart *part)
{
    bf_assert(part);

    return nlmsg_total_size(nlmsg_datalen(bf_nlpart_hdr(part)));
}

int bf_nlpart_family(const struct bf_nlpart *part)
{
    bf_assert(part);

    return bf_nlpart_hdr(part)->nlmsg_type >> 8;
}

int bf_nlpart_command(const struct bf_nlpart *part)
{
    bf_assert(part);

    return bf_nlpart_hdr(part)->nlmsg_type & BF_NLPART_FAMILY_MASK;
}

int bf_nlpart_flags(const struct bf_nlpart *part)
{
    bf_assert(part);

    return bf_nlpart_hdr(part)->nlmsg_flags;
}

uint16_t bf_nlpart_seqnr(const struct bf_nlpart *part)
{
    bf_assert(part);

    return bf_nlpart_hdr(part)->nlmsg_seq;
}

struct nlattr *bf_nlpart_attr(const struct bf_nlpart *part,
                              size_t extra_hdr_len)
{
    bf_assert(part);

    return nlmsg_attrdata(bf_nlpart_hdr(part), extra_hdr_len);
}

int bf_nlpart_attrlen(const struct bf_nlpart *part, size_t extra_hdr_len)
{
    bf_assert(part);

    return nlmsg_attrlen(bf_nlpart_hdr(part), extra_hdr_len);
}

int bf_nlpart_put_extra_header(struct bf_nlpart *part, void *data, size_t size)
{
    bf_assert(part);
    bf_assert(data);

    return nlmsg_append(part->msg, data, size, NLMSG_ALIGNTO);
}

int bf_nlpart_put_attr(struct bf_nlpart *part, uint16_t attr, const void *data,
                       size_t size)
{
    bf_assert(part);
    bf_assert(data);

    return nla_put(part->msg, attr, size, data);
}

int bf_nlpart_parse(const struct bf_nlpart *part, size_t extra_hdr_len,
                    bf_nlattr **attrs, int maxtype,
                    const struct nla_policy *policy)
{
    bf_assert(part);
    bf_assert(attrs);

    int r;

    r = nlmsg_parse(bf_nlpart_hdr(part), extra_hdr_len, attrs, maxtype - 1,
                    policy);
    if (r < 0)
        return -EINVAL;

    return 0;
}

int bf_nlpart_parse_nested(bf_nlattr *attr, bf_nlattr **attrs, int maxtype,
                           const struct nla_policy *policy)
{
    bf_assert(attr);
    bf_assert(attrs);

    return nla_parse_nested(attrs, maxtype - 1, attr, policy);
}

static void _nlpart_dump_header(const struct nlmsghdr *nlh, prefix_t *prefix)
{
    bf_assert(nlh);

    static const char *cmds[] = {
        [NFT_MSG_NEWTABLE] = "NFT_MSG_NEWTABLE",
        [NFT_MSG_GETTABLE] = "NFT_MSG_GETTABLE",
        [NFT_MSG_DELTABLE] = "NFT_MSG_DELTABLE",
        [NFT_MSG_NEWCHAIN] = "NFT_MSG_NEWCHAIN",
        [NFT_MSG_GETCHAIN] = "NFT_MSG_GETCHAIN",
        [NFT_MSG_DELCHAIN] = "NFT_MSG_DELCHAIN",
        [NFT_MSG_NEWRULE] = "NFT_MSG_NEWRULE",
        [NFT_MSG_GETRULE] = "NFT_MSG_GETRULE",
        [NFT_MSG_DELRULE] = "NFT_MSG_DELRULE",
        [NFT_MSG_NEWSET] = "NFT_MSG_NEWSET",
        [NFT_MSG_GETSET] = "NFT_MSG_GETSET",
        [NFT_MSG_DELSET] = "NFT_MSG_DELSET",
        [NFT_MSG_NEWSETELEM] = "NFT_MSG_NEWSETELEM",
        [NFT_MSG_GETSETELEM] = "NFT_MSG_GETSETELEM",
        [NFT_MSG_DELSETELEM] = "NFT_MSG_DELSETELEM",
        [NFT_MSG_NEWGEN] = "NFT_MSG_NEWGEN",
        [NFT_MSG_GETGEN] = "NFT_MSG_GETGEN",
        [NFT_MSG_TRACE] = "NFT_MSG_TRACE",
        [NFT_MSG_NEWOBJ] = "NFT_MSG_NEWOBJ",
        [NFT_MSG_GETOBJ] = "NFT_MSG_GETOBJ",
        [NFT_MSG_DELOBJ] = "NFT_MSG_DELOBJ",
        [NFT_MSG_GETOBJ_RESET] = "NFT_MSG_GETOBJ_RESET",
        [NFT_MSG_NEWFLOWTABLE] = "NFT_MSG_NEWFLOWTABLE",
        [NFT_MSG_GETFLOWTABLE] = "NFT_MSG_GETFLOWTABLE",
        [NFT_MSG_DELFLOWTABLE] = "NFT_MSG_DELFLOWTABLE",
        [NFT_MSG_GETRULE_RESET] = "NFT_MSG_GETRULE_RESET",
        [NFT_MSG_DESTROYTABLE] = "NFT_MSG_DESTROYTABLE",
        [NFT_MSG_DESTROYCHAIN] = "NFT_MSG_DESTROYCHAIN",
        [NFT_MSG_DESTROYRULE] = "NFT_MSG_DESTROYRULE",
        [NFT_MSG_DESTROYSET] = "NFT_MSG_DESTROYSET",
        [NFT_MSG_DESTROYSETELEM] = "NFT_MSG_DESTROYSETELEM",
        [NFT_MSG_DESTROYOBJ] = "NFT_MSG_DESTROYOBJ",
        [NFT_MSG_DESTROYFLOWTABLE] = "NFT_MSG_DESTROYFLOWTABLE",
    };

    uint16_t cmd = nlh->nlmsg_type & BF_NLPART_FAMILY_MASK;
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    DUMP(prefix, "struct nlmsghdr at %p", nlh);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "nlmsg_len: %u", nlh->nlmsg_len);
    DUMP(prefix, "nlmsg_type: 0x%02x | %s", nlh->nlmsg_type >> 8,
         cmd <= NFT_MSG_DESTROYFLOWTABLE ?
             cmds[nlh->nlmsg_type & BF_NLPART_FAMILY_MASK] :
             "unknown");
    DUMP(prefix, "nlmsg_flags: 0x%04x", nlh->nlmsg_flags);
    DUMP(prefix, "nlmsg_seq: %u", nlh->nlmsg_seq);
    DUMP(bf_dump_prefix_last(prefix), "nlmsg_pid: %u", nlh->nlmsg_pid);

    bf_dump_prefix_pop(prefix);
}

static void _nlpart_dump_extra_header(const void *extra_hdr,
                                      size_t extra_hdr_len, prefix_t *prefix)
{
    bf_assert(extra_hdr);

    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    DUMP(prefix, "extra header data at %p", extra_hdr);

    bf_dump_prefix_push(prefix);
    bf_dump_hex(prefix, extra_hdr, extra_hdr_len);
    bf_dump_prefix_pop(prefix);
}

static inline bool _nlattr_has_next(struct nlattr *attr, size_t remaining)
{
    struct nlattr *next = nla_next(attr, (int *)&remaining);

    return nla_ok(next, remaining);
}

static void _nlpart_dump_attr(struct nlattr *attr, int attr_len,
                              prefix_t *prefix)
{
    bf_assert(attr);

    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    while (nla_ok(attr, attr_len)) {
        DUMP((_nlattr_has_next(attr, attr_len) ? prefix :
                                                 bf_dump_prefix_last(prefix)),
             "struct nlattr at %p", attr);

        bf_dump_prefix_push(prefix);
        DUMP(prefix, "nla_len: %u", attr->nla_len);
        DUMP(prefix, "nla_type: %u", attr->nla_type);
        DUMP(bf_dump_prefix_last(prefix), "nla_data: %p", nla_data(attr));

        bf_dump_prefix_push(prefix);
        bf_dump_hex(prefix, nla_data(attr), nla_len(attr));
        bf_dump_prefix_pop(prefix);

        bf_dump_prefix_pop(prefix);

        attr = nla_next(attr, &attr_len);
    };
}

void bf_nlpart_dump(const struct bf_nlpart *part, size_t extra_hdr_len,
                    prefix_t *prefix)
{
    bf_assert(part);

    bool has_attr = bf_nlpart_attrlen(part, extra_hdr_len);
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    DUMP(prefix, "struct bf_nlpart at %p", part);
    bf_dump_prefix_push(prefix);

    _nlpart_dump_header(bf_nlpart_hdr(part), (!extra_hdr_len && !has_attr) ?
                                                 bf_dump_prefix_last(prefix) :
                                                 prefix);

    if (extra_hdr_len) {
        _nlpart_dump_extra_header(bf_nlpart_data(part), extra_hdr_len,
                                  !has_attr ? bf_dump_prefix_last(prefix) :
                                              prefix);
    }

    if (has_attr) {
        _nlpart_dump_attr(bf_nlpart_attr(part, extra_hdr_len),
                          bf_nlpart_attrlen(part, extra_hdr_len), prefix);
    }

    bf_dump_prefix_pop(prefix);
}
