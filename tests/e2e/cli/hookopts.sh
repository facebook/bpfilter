#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

# Disallow duplicated hook options
(! bfcli ruleset set --dry-run --from-str "chain ifindex BF_HOOK_XDP{ifindex=2,ifindex=3} ACCEPT")
(! bfcli ruleset set --dry-run --from-str "chain cgpath BF_HOOK_CGROUP_INGRESS{cgpath=/sys/fs/cgroup,cgpath=/sys/fs/cgroup} ACCEPT")
(! bfcli ruleset set --dry-run --from-str "chain family BF_HOOK_NF_LOCAL_IN{family=inet4,family=inet6} ACCEPT")
(! bfcli ruleset set --dry-run --from-str "chain priorities BF_HOOK_NF_LOCAL_IN{priorities=1-2,priorities=3-4} ACCEPT")