#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq fin counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq fin,syn,rst,psh,ack counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq fin,syn,rst,psh,ack,urg counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq fin,syn,rst,psh,ack,urg,ece counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq fin,syn,rst,psh,ack,urg,ece,cwr counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq syn,fin counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq cwr,fin,ack counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq invalid counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags eq fin,syn,rst,psh,ack,urg,ece,cwr,invalid counter DROP")

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not fin counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not syn counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not rst counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not psh counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not fin,syn,rst,psh,ack counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not fin,syn,rst,psh,ack,urg counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not fin,syn,rst,psh,ack,urg,ece counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not fin,syn,rst,psh,ack,urg,ece,cwr counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not invalid counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags not fin,syn,rst,psh,ack,urg,ece,cwr,invalid counter DROP")

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin,syn,rst,psh,ack counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin,syn,rst,psh,ack,urg counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin,syn,rst,psh,ack,urg,ece counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin,syn,rst,psh,ack,urg,ece,cwr counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any syn,fin counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any cwr,fin,ack counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any invalid counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin,invalid counter DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin,,syn counter DROP")

${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags all fin counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags all syn counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags all fin,syn counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags all fin,syn,rst counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags all fin,syn,rst,psh counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags any fin,fin,syn counter DROP"

(! ${BFCLI} ruleset set --dry-run --from-str "chain xdp BF_HOOK_XDP ACCEPT rule tcp.flags all fin,syn,rst,psh,ack,urg,ece,cwr,invalid counter DROP")
