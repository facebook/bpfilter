#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Disallow duplicated hook options
(! ${BFCLI} ruleset set --dry-run --from-str "chain ifindex BF_HOOK_XDP{ifindex=2,ifindex=3} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain iface BF_HOOK_XDP{iface=lo,iface=lo} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain iface_ifindex BF_HOOK_XDP{ifindex=2,iface=lo} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain ifindex_iface BF_HOOK_XDP{iface=lo,ifindex=2} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain cgpath BF_HOOK_CGROUP_SKB_INGRESS{cgpath=/sys/fs/cgroup,cgpath=/sys/fs/cgroup} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain family BF_HOOK_NF_LOCAL_IN{family=inet4,family=inet6} ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain priorities BF_HOOK_NF_LOCAL_IN{priorities=1-2,priorities=3-4} ACCEPT")
