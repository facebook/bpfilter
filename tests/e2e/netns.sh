#!/bin/bash
set -e

# Define variables
NAMESPACE="test_ns"
PROGNAME="bfe2e"
VETH_HOST="veth_host"
VETH_NS="veth_ns"
HOST_IP="10.0.0.1/24"
NS_IP="10.0.0.2/24"
HOST_IP_ADDR="10.0.0.1"
NS_IP_ADDR="10.0.0.2"

log() {
    local ORANGE='\033[1;33m'
    local RESET='\033[0m'
    echo -e "${ORANGE}[.]${RESET} $1"
}

success() {
    local GREEN='\033[1;32m'
    local RESET='\033[0m'
    echo -e "${GREEN}[+]${RESET} -> Success" >&2
}

failure() {
    local RED='\033[1;31m'
    local RESET='\033[0m'
    echo -e "${RED}[-]${RESET} -> Failure" >&2
    exit 1
}

# Function to cleanup on exit or error
cleanup() {
    log "Cleanup"

    if [ -n "$BPFILTER_PID" ]; then
        kill $BPFILTER_PID 2>/dev/null || true
    fi

    if [ "${1:-0}" -ne 0 ] && [ -f "$BPFILTER_OUTPUT_FILE" ]; then
        log "bpfilter output:"
        cat "$BPFILTER_OUTPUT_FILE"
    fi

    ip netns del ${NAMESPACE} 2>/dev/null || true
    exit ${1:-0}
}

# Set trap to ensure cleanup happens
trap 'cleanup $?' EXIT
trap 'cleanup 1' INT TERM


################################################################################
#
# Configure the network namespace
#
################################################################################

ip netns add ${NAMESPACE}
ip link add ${VETH_HOST} type veth peer name ${VETH_NS}

ip link set ${VETH_NS} netns ${NAMESPACE}

ip addr add ${HOST_IP} dev ${VETH_HOST}
ip netns exec ${NAMESPACE} ip addr add ${NS_IP} dev ${VETH_NS}

ip link set ${VETH_HOST} up
ip netns exec ${NAMESPACE} ip link set ${VETH_NS} up
ip netns exec ${NAMESPACE} ip link set lo up

HOST_IFINDEX=$(ip -o link show ${VETH_HOST} | awk '{print $1}' | cut -d: -f1)
NS_IFINDEX=$(ip netns exec ${NAMESPACE} ip -o link show ${VETH_NS} | awk '{print $1}' | cut -d: -f1)

log "Network interfaces configured:"
log "  ${HOST_IFINDEX}: ${VETH_HOST} @ ${HOST_IP_ADDR}"
log "  ${NS_IFINDEX}: ${VETH_NS} @ ${NS_IP_ADDR}"

log "[TEST] Validate initial connectivity"
ip netns exec ${NAMESPACE} ping -c 1 ${HOST_IP_ADDR} > /dev/null 2>&1 && success || failure


################################################################################
#
# Start bpfilter
#
################################################################################

log "Starting bpfilter in background..."
BPFILTER_OUTPUT_FILE=$(mktemp)
bpfilter --transient --verbose debug --verbose bpf > "$BPFILTER_OUTPUT_FILE" 2>&1 &
BPFILTER_PID=$!

# Wait for bpfilter to initialize
sleep 0.25


################################################################################
#
# Run tests
#
################################################################################

log "[TEST] Can't attach chain to netns iface from host"
! bfcli ruleset set --str "chain BF_HOOK_XDP{ifindex=${NS_IFINDEX},name=${PROGNAME}} policy ACCEPT rule ip4.proto icmp counter DROP" > /dev/null 2>&1 && success || failure

log "[TEST] Can ping host iface from netns"
ip netns exec ${NAMESPACE} ping -c 1 -W 0.25 ${HOST_IP_ADDR} > /dev/null 2>&1 && success || failure

log "[TEST] Attach chain to host iface"
bfcli ruleset set --str "chain BF_HOOK_XDP{ifindex=${HOST_IFINDEX},name=${PROGNAME}} policy ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Can't ping host iface from netns"
! ip netns exec ${NAMESPACE} ping -c 1 -W 0.25 ${HOST_IP_ADDR} > /dev/null 2>&1 && success || failure

log "[TEST] Pings have been blocked on ingress"
bpftool --json map dump name ${PROGNAME}_cmp | jq --exit-status '.[0].formatted.value.packets == 1' > /dev/null 2>&1 && success || failure

log "Flushing the ruleset"
bfcli ruleset flush && success || failure

log "[TEST] Can't attach chain to host iface from netns"
! ip netns exec ${NAMESPACE} bfcli ruleset set --str "chain BF_HOOK_XDP{ifindex=${HOST_IFINDEX},name=${PROGNAME}} policy ACCEPT rule ip4.proto icmp counter DROP" > /dev/null 2>&1 && success || failure

log "[TEST] Can ping the netns iface from the host"
ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1  && success || failure

log "[TEST] Attach chain to the netns iface"
ip netns exec ${NAMESPACE} bfcli ruleset set --str "chain BF_HOOK_XDP{ifindex=${NS_IFINDEX},name=${PROGNAME}} policy ACCEPT rule ip4.proto icmp counter DROP" > /dev/null 2>&1 && success || failure

log "[TEST] Can't ping the netns iface from the host"
! ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure

log "[TEST] Pings have been blocked on ingress"
bpftool --json map dump name ${PROGNAME}_cmp | jq --exit-status '.[0].formatted.value.packets == 1' > /dev/null 2>&1 && success || failure

log "Flushing the ruleset"
bfcli ruleset flush && success || failure

log "[TEST] Attach chain to the netns iface"
ip netns exec ${NAMESPACE} bfcli ruleset set --str "chain BF_HOOK_NF_LOCAL_IN{name=${PROGNAME}} policy ACCEPT" > /dev/null 2>&1 && success || failure

log "[TEST] Pinging the host interface should not update the counters of the program in the namespace"
ping -c 1 -W 0.25 ${HOST_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${PROGNAME}_cmp | jq --exit-status '.[0].formatted.value.packets == 0' > /dev/null 2>&1 && success || failure

log "[TEST] Pinging the namespace interface should not update the counters of the program in the namespace"
ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${PROGNAME}_cmp | jq --exit-status '.[0].formatted.value.packets == 1' > /dev/null 2>&1 && success || failure


################################################################################
#
# Cleanup
#
################################################################################

kill $BPFILTER_PID
exit 0
