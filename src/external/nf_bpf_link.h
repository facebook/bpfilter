/* SPDX-License-Identifier: GPL-2.0 */

#include <stdint.h>

struct sk_buff;
struct sock;
struct net;
struct netdev_name_node;
typedef unsigned int __u32;

typedef __u32 u32;
typedef u32 xdp_features_t;

struct list_head
{
    struct list_head *next;
    struct list_head *prev;
};

struct bpf_nf_ctx
{
    const struct nf_hook_state *state;
    struct sk_buff *skb;
};

struct nf_hook_state
{
    uint8_t hook;
    uint8_t pf;
    struct net_device *in;
    struct net_device *out;
    struct sock *sk;
    struct net *net;
    int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};

struct net_device
{
    char name[16];
    struct netdev_name_node *name_node;
    struct dev_ifalias *ifalias;
    long unsigned int mem_end;
    long unsigned int mem_start;
    long unsigned int base_addr;
    long unsigned int state;
    struct list_head dev_list;
    struct list_head napi_list;
    struct list_head unreg_list;
    struct list_head close_list;
    struct list_head ptype_all;
    struct list_head ptype_specific;

    struct
    {
        struct list_head upper;
        struct list_head lower;
    } adj_list;

    unsigned int flags;
    xdp_features_t xdp_features;
    long long unsigned int priv_flags;
    const struct net_device_ops *netdev_ops;
    const struct xdp_metadata_ops *xdp_metadata_ops;
    int ifindex;
    short unsigned int gflags;
};
