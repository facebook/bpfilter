#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
ping -c 1 -W 0.1 ${NS_IP_ADDR}

# Terminal verdicts skip the suffix and policy; CONTINUE reaches the suffix.
for matcher in '' '(meta.sport) not in {}' 'meta.probability eq 100%'; do
    for verdict in ACCEPT DROP NEXT CONTINUE; do
        ${FROM_NS} ${BFCLI} chain set --from-str \
            "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} NEXT \
             rule $matcher counter $verdict rule counter DROP"
        case $verdict in
            ACCEPT|NEXT) ping -c 1 -W 0.1 ${NS_IP_ADDR} ;;
            DROP|CONTINUE) (! ping -c 1 -W 0.1 ${NS_IP_ADDR}) ;;
        esac
        test "$(get_counter c 0)" -gt 0
        if [ "$verdict" = CONTINUE ]; then
            test "$(get_counter c 1)" -gt 0
        else
            test "$(get_counter c 1)" = "0"
        fi
        test "$(get_counter c 2)" = "0"
        ${FROM_NS} ${BFCLI} ruleset flush
    done
done

# CONTINUE can also reach policy, with logging and state-map fixups retained.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} NEXT \
     rule counter log every 1s CONTINUE"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter c 0)" -gt 0
test "$(get_counter c 1)" -gt 0
${FROM_NS} ${BFCLI} ruleset flush

# Disabled and conditional rules precede an unconditional logged DROP.
# A no-op lookup does not make a real condition unconditional.
for matcher in '(tcp.dport) not in {}' \
    '(ip4.daddr) not in {} ip4.proto tcp' \
    '(meta.sport) not in {} ip4.proto tcp' \
    'ip4.proto tcp (meta.sport) not in {}'; do
    ${FROM_NS} ${BFCLI} chain set --from-str \
        "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} NEXT \
         set s (ip4.daddr) in {} \
         rule (ip4.daddr) in s counter DROP \
         rule $matcher counter NEXT \
         rule counter CONTINUE \
         rule counter log DROP \
         rule counter ACCEPT"
    (! ping -c 1 -W 0.1 ${NS_IP_ADDR})
    test "$(get_counter c 0)" = "0"
    test "$(get_counter c 1)" = "0"
    test "$(get_counter c 2)" -gt 0
    test "$(get_counter c 3)" -gt 0
    test "$(get_counter c 4)" = "0"

    # Adding a condition to DROP makes the original suffix/index reachable.
    ${FROM_NS} ${BFCLI} chain update --from-str \
        "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} NEXT \
         set s (ip4.daddr) in {} \
         rule (ip4.daddr) in s counter DROP \
         rule $matcher counter NEXT \
         rule counter CONTINUE \
         rule ip4.proto tcp counter log DROP \
         rule counter ACCEPT"
    ping -c 1 -W 0.1 ${NS_IP_ADDR}
    test "$(get_counter c 0)" = "0"
    test "$(get_counter c 1)" = "0"
    test "$(get_counter c 2)" -gt 0
    test "$(get_counter c 3)" = "0"
    test "$(get_counter c 4)" -gt 0
    ${FROM_NS} ${BFCLI} ruleset flush
done

# REDIRECT is terminal too; load without attaching or forwarding traffic.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain c BF_HOOK_XDP NEXT \
     rule counter log REDIRECT ${NS_IFINDEX} out \
     rule counter DROP"
${FROM_NS} ${BFCLI} ruleset flush
