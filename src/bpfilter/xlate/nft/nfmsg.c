/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/xlate/nft/nfmsg.h"

#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>

#include <errno.h>
#include <limits.h>
#include <netlink/msg.h>

#include "core/helper.h"
#include "core/logger.h"

struct bf_nfmsg
{
    struct nl_msg *msg;
};

static const struct nla_policy _bf_nf_table_policy[__NFTA_TABLE_MAX] = {
    [NFTA_TABLE_NAME] = {.type = NLA_STRING},
    [NFTA_TABLE_FLAGS] = {.type = NLA_U32},
    [NFTA_TABLE_HANDLE] = {.type = NLA_U64},
    [NFTA_TABLE_USERDATA] = {.type = NLA_BINARY},
};
const bf_nfpolicy *bf_nf_table_policy = _bf_nf_table_policy;

static const struct nla_policy _bf_nf_chain_policy[__NFTA_CHAIN_MAX] = {
    [NFTA_CHAIN_TABLE] = {.type = NLA_STRING},
    [NFTA_CHAIN_HANDLE] = {.type = NLA_U64},
    [NFTA_CHAIN_NAME] = {.type = NLA_STRING},
    [NFTA_CHAIN_HOOK] = {.type = NLA_NESTED},
    [NFTA_CHAIN_POLICY] = {.type = NLA_U32},
    [NFTA_CHAIN_TYPE] = {.type = NLA_STRING},
    [NFTA_CHAIN_COUNTERS] = {.type = NLA_NESTED},
    [NFTA_CHAIN_FLAGS] = {.type = NLA_U32},
    [NFTA_CHAIN_ID] = {.type = NLA_U32},
    [NFTA_CHAIN_USERDATA] = {.type = NLA_BINARY},
};
const bf_nfpolicy *bf_nf_chain_policy = _bf_nf_chain_policy;

static const struct nla_policy _bf_nf_hook_policy[__NFTA_HOOK_MAX] = {
    [NFTA_HOOK_HOOKNUM] = {.type = NLA_U32},
    [NFTA_HOOK_PRIORITY] = {.type = NLA_U32},
    [NFTA_HOOK_DEV] = {.type = NLA_STRING},
};
const bf_nfpolicy *bf_nf_hook_policy = _bf_nf_hook_policy;

static const struct nla_policy _bf_nf_rule_policy[__NFTA_RULE_MAX] = {
    [NFTA_RULE_TABLE] = {.type = NLA_STRING},
    [NFTA_RULE_CHAIN] = {.type = NLA_STRING},
    [NFTA_RULE_HANDLE] = {.type = NLA_U64},
    [NFTA_RULE_EXPRESSIONS] = {.type = NLA_NESTED},
    [NFTA_RULE_COMPAT] = {.type = NLA_NESTED},
    [NFTA_RULE_POSITION] = {.type = NLA_U64},
    [NFTA_RULE_USERDATA] = {.type = NLA_BINARY},
    [NFTA_RULE_ID] = {.type = NLA_U32},
    [NFTA_RULE_POSITION_ID] = {.type = NLA_U32},
    [NFTA_RULE_CHAIN_ID] = {.type = NLA_U32},
};
const bf_nfpolicy *bf_nf_rule_policy = _bf_nf_rule_policy;

static const struct nla_policy _bf_nf_expr_policy[__NFTA_EXPR_MAX] = {
    [NFTA_EXPR_NAME] = {.type = NLA_STRING},
    [NFTA_EXPR_DATA] = {.type = NLA_NESTED},
};
const bf_nfpolicy *bf_nf_expr_policy = _bf_nf_expr_policy;

static const struct nla_policy _bf_nf_counter_policy[NFTA_COUNTER_MAX + 1] = {
    [NFTA_COUNTER_PACKETS] = {.type = NLA_U64},
    [NFTA_COUNTER_BYTES] = {.type = NLA_U64},
};
const bf_nfpolicy *bf_nf_counter_policy = _bf_nf_counter_policy;

static const struct nla_policy _bf_nf_payload_policy[__NFTA_PAYLOAD_MAX] = {
    [NFTA_PAYLOAD_SREG] = {.type = NLA_U32},
    [NFTA_PAYLOAD_DREG] = {.type = NLA_U32},
    [NFTA_PAYLOAD_BASE] = {.type = NLA_U32},
    [NFTA_PAYLOAD_OFFSET] = {.type = NLA_U32},
    [NFTA_PAYLOAD_LEN] = {.type = NLA_U32},
    [NFTA_PAYLOAD_CSUM_TYPE] = {.type = NLA_U32},
    [NFTA_PAYLOAD_CSUM_OFFSET] = {.type = NLA_U32},
    [NFTA_PAYLOAD_CSUM_FLAGS] = {.type = NLA_U32},
};
const bf_nfpolicy *bf_nf_payload_policy = _bf_nf_payload_policy;

static const struct nla_policy _bf_nf_cmp_policy[__NFTA_CMP_MAX] = {
    [NFTA_CMP_SREG] = {.type = NLA_U32},
    [NFTA_CMP_OP] = {.type = NLA_U32},
    [NFTA_CMP_DATA] = {.type = NLA_NESTED},
};
const bf_nfpolicy *bf_nf_cmp_policy = _bf_nf_cmp_policy;

static const struct nla_policy _bf_nf_immediate_policy[__NFTA_IMMEDIATE_MAX] = {
    [NFTA_IMMEDIATE_DREG] = {.type = NLA_U32},
    [NFTA_IMMEDIATE_DATA] = {.type = NLA_NESTED},
};
const bf_nfpolicy *bf_nf_immediate_policy = _bf_nf_immediate_policy;

static const struct nla_policy _bf_nf_data_policy[__NFTA_DATA_MAX] = {
    [NFTA_DATA_VALUE] = {.type = NLA_BINARY},
    [NFTA_DATA_VERDICT] = {.type = NLA_NESTED},
};
const bf_nfpolicy *bf_nf_data_policy = _bf_nf_data_policy;

static const struct nla_policy _bf_nf_verdict_policy[__NFTA_VERDICT_MAX] = {
    [NFTA_VERDICT_CODE] = {.type = NLA_U32},
    [NFTA_VERDICT_CHAIN] = {.type = NLA_STRING},
    [NFTA_VERDICT_CHAIN_ID] = {.type = NLA_U32},
};
const bf_nfpolicy *bf_nf_verdict_policy = _bf_nf_verdict_policy;

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

int bf_nfmsg_new_done(struct bf_nfmsg **msg)
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

    nlh = nlmsg_put(_msg->msg, 0, 0, NLMSG_DONE, 0, NLM_F_MULTI);
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

size_t bf_nfattr_data_len(bf_nfattr *attr)
{
    bf_assert(attr);

    return (size_t)nla_len(attr);
}

bool bf_nfattr_is_ok(bf_nfattr *attr, size_t remaining)
{
    bf_assert(attr);
    bf_assert(remaining < INT_MAX);

    return nla_ok(attr, (int)remaining);
}

bf_nfattr *bf_nfattr_next(bf_nfattr *attr, size_t *remaining)
{
    bf_assert(attr);
    bf_assert(remaining && *remaining < INT_MAX);

    int _remaining = (int)*remaining;

    attr = nla_next(attr, &_remaining);
    *remaining = (size_t)_remaining;

    return attr;
}

int bf_nfmsg_nest_init(struct bf_nfnest *nest, struct bf_nfmsg *parent,
                       uint16_t type)
{
    bf_assert(nest);
    bf_assert(parent);

    bf_nfattr *attr;

    attr = nla_nest_start(parent->msg, type);
    if (!attr)
        return -ENOMEM;

    nest->attr = attr;
    nest->parent = parent;

    return 0;
}

void bf_nfnest_cleanup(struct bf_nfnest *nest)
{
    bf_assert(nest);

    nla_nest_end(nest->parent->msg, nest->attr);
}
