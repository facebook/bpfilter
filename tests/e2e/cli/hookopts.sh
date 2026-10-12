#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

# Disallow duplicated hook options
(! ${BFCLI} ruleset set --dry-run --from-str "chain ifindex BF_HOOK_XDP{ifindex=2,ifindex=3} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain cgpath BF_HOOK_CGROUP_SKB_INGRESS{cgpath=/sys/fs/cgroup,cgpath=/sys/fs/cgroup} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain family BF_HOOK_NF_LOCAL_IN{family=inet4,family=inet6} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain priorities BF_HOOK_NF_LOCAL_IN{priorities=1-2,priorities=3-4} ACCEPT")

(! ${BFCLI} ruleset set --dry-run --from-str "chain defrag BF_HOOK_NF_LOCAL_IN{priorities=1-2,defrag=yes,defrag=no} ACCEPT")

# defrag= is only supported by Netfilter chains, and only takes yes or no
${BFCLI} ruleset set --dry-run --from-str "chain defrag BF_HOOK_NF_LOCAL_IN{priorities=1-2,defrag=yes} ACCEPT"
${BFCLI} ruleset set --dry-run --from-str "chain defrag BF_HOOK_NF_PRE_ROUTING{defrag=no,priorities=1-2} ACCEPT"
(! ${BFCLI} ruleset set --dry-run --from-str "chain defrag BF_HOOK_XDP{ifindex=2,defrag=yes} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain defrag BF_HOOK_TC_INGRESS{ifindex=2,defrag=no} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain defrag BF_HOOK_NF_LOCAL_IN{priorities=1-2,defrag=maybe} ACCEPT")
