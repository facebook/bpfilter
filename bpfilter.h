/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_H
#define NET_BPFILTER_H

#include <linux/if.h>
#include <linux/const.h>

#define BPFILTER_STANDARD_TARGET        ""
#define BPFILTER_ERROR_TARGET           "ERROR"

enum {
	BPFILTER_IPT_SO_SET_REPLACE = 64,
	BPFILTER_IPT_SO_SET_ADD_COUNTERS = 65,
	BPFILTER_IPT_SET_MAX,
};

enum {
	BPFILTER_IPT_SO_GET_INFO = 64,
	BPFILTER_IPT_SO_GET_ENTRIES = 65,
	BPFILTER_IPT_SO_GET_REVISION_MATCH = 66,
	BPFILTER_IPT_SO_GET_REVISION_TARGET = 67,
	BPFILTER_IPT_GET_MAX,
};

enum {
	BPFILTER_XT_TABLE_MAXNAMELEN = 32,
	BPFILTER_FUNCTION_MAXNAMELEN = 30,
	BPFILTER_EXTENSION_MAXNAMELEN = 29,
};

enum {
	BPFILTER_NF_DROP = 0,
	BPFILTER_NF_ACCEPT = 1,
	BPFILTER_NF_STOLEN = 2,
	BPFILTER_NF_QUEUE = 3,
	BPFILTER_NF_REPEAT = 4,
	BPFILTER_NF_STOP = 5,
	BPFILTER_NF_MAX_VERDICT = BPFILTER_NF_STOP,
	BPFILTER_RETURN = (-BPFILTER_NF_REPEAT - 1),
};

enum {
	BPFILTER_INET_HOOK_PRE_ROUTING = 0,
	BPFILTER_INET_HOOK_LOCAL_IN = 1,
	BPFILTER_INET_HOOK_FORWARD = 2,
	BPFILTER_INET_HOOK_LOCAL_OUT = 3,
	BPFILTER_INET_HOOK_POST_ROUTING = 4,
	BPFILTER_INET_HOOK_MAX,
};

enum {
	BPFILTER_IPT_F_MASK = 0x03,
	BPFILTER_IPT_INV_MASK = 0x7f
};

struct bpfilter_ipt_match {
	union {
		struct {
			__u16 match_size;
			char name[BPFILTER_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 match_size;
			void *match;
		} kernel;
		__u16 match_size;
	} u;
	unsigned char data[0];
};

struct bpfilter_ipt_target {
	union {
		struct {
			__u16 target_size;
			char name[BPFILTER_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 target_size;
			void *target;
		} kernel;
		__u16 target_size;
	} u;
	unsigned char data[0];
};

struct bpfilter_ipt_standard_target {
	struct bpfilter_ipt_target target;
	int verdict;
};

struct bpfilter_ipt_error_target {
	struct bpfilter_ipt_target target;
	char error_name[BPFILTER_FUNCTION_MAXNAMELEN];
};

struct bpfilter_ipt_get_info {
	char name[BPFILTER_XT_TABLE_MAXNAMELEN];
	__u32 valid_hooks;
	__u32 hook_entry[BPFILTER_INET_HOOK_MAX];
	__u32 underflow[BPFILTER_INET_HOOK_MAX];
	__u32 num_entries;
	__u32 size;
};

struct bpfilter_ipt_counters {
	__u64 packet_cnt;
	__u64 byte_cnt;
};

struct bpfilter_ipt_counters_info {
	char name[BPFILTER_XT_TABLE_MAXNAMELEN];
	__u32 num_counters;
	struct bpfilter_ipt_counters counters[0];
};

struct bpfilter_ipt_get_revision {
	char name[BPFILTER_EXTENSION_MAXNAMELEN];
	__u8 revision;
};

struct bpfilter_ipt_ip {
	__u32 src;
	__u32 dst;
	__u32 src_mask;
	__u32 dst_mask;
	char in_iface[IFNAMSIZ];
	char out_iface[IFNAMSIZ];
	__u8 in_iface_mask[IFNAMSIZ];
	__u8 out_iface_mask[IFNAMSIZ];
	__u16 protocol;
	__u8 flags;
	__u8 invflags;
};

struct bpfilter_ipt_entry {
	struct bpfilter_ipt_ip ip;
	__u32 bfcache;
	__u16 target_offset;
	__u16 next_offset;
	__u32 comefrom;
	struct bpfilter_ipt_counters counters;
	__u8 elems[0];
};

struct bpfilter_ipt_standard_entry {
	struct bpfilter_ipt_entry entry;
	struct bpfilter_ipt_standard_target target;
};

struct bpfilter_ipt_error_entry {
	struct bpfilter_ipt_entry entry;
	struct bpfilter_ipt_error_target target;
};

struct bpfilter_ipt_get_entries {
	char name[BPFILTER_XT_TABLE_MAXNAMELEN];
	__u32 size;
	struct bpfilter_ipt_entry entries[0];
};

struct bpfilter_ipt_replace {
	char name[BPFILTER_XT_TABLE_MAXNAMELEN];
	__u32 valid_hooks;
	__u32 num_entries;
	__u32 size;
	__u32 hook_entry[BPFILTER_INET_HOOK_MAX];
	__u32 underflow[BPFILTER_INET_HOOK_MAX];
	__u32 num_counters;
	struct bpfilter_ipt_counters *cntrs;
	struct bpfilter_ipt_entry entries[0];
};

#endif // NET_BPFILTER_H
