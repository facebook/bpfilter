/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "xlate/nft/nfmsg.h"

#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>

#include <errno.h>
#include <netlink/msg.h>

#include "core/logger.h"
#include "shared/helper.h"

struct bf_nfmsg
{
    struct nl_msg *msg;
};

int bf_nfmsg_new(struct bf_nfmsg **msg, uint8_t command, uint32_t seqnr)
{
    bf_assert(msg);

    _cleanup_bf_nfmsg_ struct bf_nfmsg *_msg = NULL;
    struct nlmsghdr *nlh;
    struct nfgenmsg extra_hdr = {
        .nfgen_family = AF_INET,
        .version = NFNETLINK_V0,
        .res_id = 0,
    };
    int r;

    _msg = calloc(1, sizeof(*_msg));
    if (!_msg)
        return -ENOMEM;

    _msg->msg = nlmsg_alloc();
    if (!_msg->msg)
        return -ENOMEM;

    nlh = nlmsg_put(_msg->msg, 0, seqnr, NFNL_SUBSYS_NFTABLES << 8 | command, 0,
                    0);
    if (!nlh)
        return bf_err_code(-ENOMEM, "failed to insert Netlink header");

    r = nlmsg_append(_msg->msg, &extra_hdr, sizeof(extra_hdr), NLMSG_ALIGNTO);
    if (r)
        return bf_err_code(r, "failed to insert Netfilter extra header");

    *msg = TAKE_PTR(_msg);

    return 0;
}

int bf_nfmsg_new_from_nlmsghdr(struct bf_nfmsg **msg, struct nlmsghdr *nlh)
{
    bf_assert(msg);
    bf_assert(nlh);

    _cleanup_bf_nfmsg_ struct bf_nfmsg *_msg = NULL;

    if (nlh->nlmsg_type >> 8 != NFNL_SUBSYS_NFTABLES) {
        return bf_err_code(-EINVAL, "invalid Netlink message type: %u",
                           nlh->nlmsg_type);
    }

    if ((size_t)nlmsg_datalen(nlh) < sizeof(struct nfgenmsg)) {
        return bf_err_code(-EINVAL, "invalid Netlink message payload size: %d",
                           nlmsg_datalen(nlh));
    }

    _msg = calloc(1, sizeof(*_msg));
    if (!_msg)
        return -ENOMEM;

    _msg->msg = nlmsg_convert(nlh);
    if (!_msg->msg)
        return -ENOMEM;

    *msg = TAKE_PTR(_msg);

    return 0;
}

void bf_nfmsg_free(struct bf_nfmsg **msg)
{
    bf_assert(msg);

    if (!*msg)
        return;

    nlmsg_free((*msg)->msg);
    free(*msg);
    *msg = NULL;
}

struct nlmsghdr *bf_nfmsg_hdr(const struct bf_nfmsg *msg)
{
    bf_assert(msg);

    return nlmsg_hdr(msg->msg);
}

size_t bf_nfmsg_data_len(const struct bf_nfmsg *msg)
{
    bf_assert(msg);

    return nlmsg_datalen(bf_nfmsg_hdr(msg));
}

size_t bf_nfmsg_len(const struct bf_nfmsg *msg)
{
    bf_assert(msg);

    return nlmsg_total_size(bf_nfmsg_data_len(msg));
}

uint8_t bf_nfmsg_command(const struct bf_nfmsg *msg)
{
    bf_assert(msg);

    return bf_nfmsg_hdr(msg)->nlmsg_type & 0xff;
}

uint32_t bf_nfmsg_seqnr(const struct bf_nfmsg *msg)
{
    bf_assert(msg);

    return bf_nfmsg_hdr(msg)->nlmsg_seq;
}

int bf_nfmsg_attr_push(struct bf_nfmsg *msg, uint16_t type, const void *data,
                       size_t len)
{
    bf_assert(msg);
    bf_assert(data);

    return nla_put(msg->msg, type, len, data);
}

int bf_nfmsg_parse(const struct bf_nfmsg *msg, bf_nfattr **attrs, int maxtype,
                   const bf_nfpolicy *policy)
{
    bf_assert(msg);
    bf_assert(attrs);

    return nlmsg_parse(bf_nfmsg_hdr(msg), sizeof(struct nfgenmsg), attrs,
                       maxtype - 1, policy);
}

int bf_nfattr_parse(bf_nfattr *attr, bf_nfattr **attrs, int maxtype,
                    const bf_nfpolicy *policy)
{
    bf_assert(attr);
    bf_assert(attrs);

    return nla_parse_nested(attrs, maxtype - 1, attr, policy);
}

void *bf_nfattr_data(bf_nfattr *attr)
{
    bf_assert(attr);

    return nla_data(attr);
}
