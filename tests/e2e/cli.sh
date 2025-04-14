#!/bin/bash
set -e

# Define variables
NAMESPACE="test_ns"
COUNTERS_MAP_NAME="counters_map"
VETH_HOST="veth_host"
VETH_NS="veth_ns"
HOST_IP="10.0.0.1/24"
NS_IP="10.0.0.2/24"
HOST_IP_ADDR="10.0.0.1"
NS_IP_ADDR="10.0.0.2"

BLUE='\033[0;34m'
BLUE_BOLD='\033[1;34m'
GREEN='\033[0;32m'
GREEN_BOLD='\033[1;32m'
RED='\033[0;31m'
RED_BOLD='\033[1;31m'
YELLOW='\033[0;33m'
YELLOW_BOLD='\033[1;33m'
RESET='\033[0m'

log() {
    echo -e "${BLUE}[.] ${BLUE_BOLD}$1${RESET}"
}

expect_result() {
    local description="$1"
    local expected_result="$2"  # 0 = success, non-zero = failure
    shift 2

    # Build the command string for eval
    local cmd="$*"

    # Capture both stdout and stderr
    local output
    local result=0
    output=$(eval "$cmd" 2>&1) || result=$?

    # Check if the result matches the expected result
    if { [ "$expected_result" -eq 0 ] && [ $result -eq 0 ]; } ||
       { [ "$expected_result" -ne 0 ] && [ $result -ne 0 ]; }; then
        # Success case
        echo -e "${GREEN}[+] -> Success: ${GREEN_BOLD}${description}${RESET}" >&2

        return 0
    else
        # Failure case
        echo -e "${RED}[-] -> Failure: ${RED_BOLD}${description}${RESET}" >&2

        # Print the command that was executed
        echo -e "${YELLOW}Command:${RESET} $cmd" >&2

        # Print the captured output
        echo -e "${YELLOW}Output:${RESET}" >&2
        echo "$output" >&2
        echo >&2

        return 1
    fi
}

# Wrapper function to maintain backward compatibility for expect_success
expect_success() {
    local description="$1"
    shift
    expect_result "$description" 0 "$@"
}

# Wrapper function to maintain backward compatibility for expect_failure
expect_failure() {
    local description="$1"
    shift
    expect_result "$description" 1 "$@"
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

log "[SUITE] Setup"
expect_success "validate namespace connectivity" \
    ip netns exec ${NAMESPACE} ping -c 1 ${HOST_IP_ADDR}


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

log "[SUITE] chain set"
expect_failure "no chain defined in --from-str" \
    bfcli chain set --from-str \"\"
expect_failure "multiple chains defined in --from-str, no --name" \
    bfcli chain set --from-str \"chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT\"
expect_failure "multiple chains defined in --from-str, --name does not exist" \
    bfcli chain set --name invalid --from-str \"chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, do not attach" \
    bfcli chain set --from-str \"chain chain_set_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, attach" \
    bfcli chain set --from-str \"chain chain_set_xdp_1 BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT\"
expect_success "multiple chains defined in --from-str, do not attach" \
    bfcli chain set --name chain_set_tc_0 --from-str \"chain chain_set_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_set_tc_1 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "multiple chains defined in --from-str, attach" \
    bfcli chain set --name chain_set_tc_2 --from-str \"chain chain_set_tc_2 BF_HOOK_TC_EGRESS\{ifindex=${HOST_IFINDEX}\} ACCEPT chain chain_set_tc_3 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "replace a chain that is not attached, do not attach the new one" \
    bfcli chain set --from-str \"chain chain_set_xdp_0 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "replace a chain that is not attached, attach the new one" \
    bfcli chain set --from-str \"chain chain_set_tc_0 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=101-102\} ACCEPT\"
expect_success "replace a chain that is attached, do not attach the new one" \
    bfcli chain set --from-str \"chain chain_set_xdp_1 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "replace a chain that is attached, attach the new one" \
    bfcli chain set --from-str \"chain chain_set_tc_2 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=103-104\} ACCEPT\"
expect_success "flush chain_set_xdp_0" \
    bfcli chain flush --name chain_set_xdp_0
expect_success "flush chain_set_xdp_1" \
    bfcli chain flush --name chain_set_xdp_1
expect_success "flush chain_set_tc_0" \
    bfcli chain flush --name chain_set_tc_0
expect_success "flush chain_set_tc_2" \
    bfcli chain flush --name chain_set_tc_2
expect_failure "ensure removed chain can't be fetched" \
    bfcli chain get --name chain_set_tc_2

log "[SUITE] chain load"
# No chain found
expect_failure "no chain defined in --from-str" \
    bfcli chain load --from-str \"\"
# Single chain found
expect_failure "single chain defined in --from-str, invalid --name" \
    bfcli chain load --name invalid_name --from-str \"chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, no --name" \
    bfcli chain load --from-str \"chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, select with valid --name" \
    bfcli chain load --name chain_load_xdp_2 --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
expect_success "get chain_load_xdp_1" \
    bfcli chain get --name chain_load_xdp_1
expect_success "get chain_load_xdp_2" \
    bfcli chain get --name chain_load_xdp_2
expect_success "flush chain_load_xdp_1" \
    bfcli chain flush --name chain_load_xdp_1
expect_success "flush chain_load_xdp_2" \
    bfcli chain flush --name chain_load_xdp_2
# Multiple chains found
expect_failure "multiple chains defined in --from-str, no --name" \
    bfcli chain load --from-str \"chain chain_load_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_1 BF_HOOK_TC_INGRESS ACCEPT\"
expect_failure "multiple chains defined in --from-str, invalid --name" \
    bfcli chain load --name invalid --from-str \"chain chain_load_tc_2 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_3 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "multiple chains defined in --from-str, valid --name" \
    bfcli chain load --name chain_load_tc_4 --from-str \"chain chain_load_tc_4 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_5 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "get chain_load_tc_4" \
    bfcli chain get --name chain_load_tc_4
expect_success "flush chain_load_tc_4" \
    bfcli chain flush --name chain_load_tc_4

log "[SUITE] chain attach"
# Failures
expect_success "load an XDP chain" \
    bfcli chain load --from-str \"chain chain_attach_0 BF_HOOK_XDP ACCEPT\"
expect_failure "fail to attach with unsupported options" \
    bfcli chain attach --name chain_attach_0 --option family=inet4 --option priorities=101-102
expect_success "ensure hasn't been unloaded" \
    bfcli chain get --name chain_attach_0
expect_success "flush the chain" \
    bfcli chain flush --name chain_attach_0
# XDP
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_xdp_0" \
    bfcli chain load --from-str \"chain chain_attach_xdp_0 BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_xdp_1" \
    bfcli chain load --from-str \"chain chain_attach_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "attach chain_attach_xdp_0" \
    bfcli chain attach --name chain_attach_xdp_0 --option ifindex=${HOST_IFINDEX}
expect_failure "fails to attach chain_attach_xdp_1" \
    bfcli chain attach --name chain_attach_xdp_1 --option ifindex=${HOST_IFINDEX}
expect_failure "pings from host to netns are blocked by XDP chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_xdp_0" \
    bfcli chain flush --name chain_attach_xdp_0
expect_success "flush chain_attach_xdp_1" \
    bfcli chain flush --name chain_attach_xdp_1
# TC
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_tc_0" \
    bfcli chain load --from-str \"chain chain_attach_tc_0 BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_tc_1" \
    bfcli chain load --from-str \"chain chain_attach_tc_1 BF_HOOK_TC_EGRESS ACCEPT\"
expect_success "attach chain_attach_tc_0" \
    bfcli chain attach --name chain_attach_tc_0 --option ifindex=${HOST_IFINDEX}
expect_success "attach chain_attach_tc_1" \
    bfcli chain attach --name chain_attach_tc_1 --option ifindex=${HOST_IFINDEX}
expect_failure "pings from host to netns are blocked by TC chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_tc_0" \
    bfcli chain flush --name chain_attach_tc_0
expect_success "flush chain_attach_tc_1" \
    bfcli chain flush --name chain_attach_tc_1
# cgroup
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_cgroup_0" \
    bfcli chain load --from-str \"chain chain_attach_cgroup_0 BF_HOOK_CGROUP_INGRESS ACCEPT\"
expect_success "load chain_attach_cgroup_1" \
    bfcli chain load --from-str \"chain chain_attach_cgroup_1 BF_HOOK_CGROUP_INGRESS ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "attach chain_attach_cgroup_0" \
    bfcli chain attach --name chain_attach_cgroup_0 --option cgpath=/sys/fs/cgroup/user.slice
expect_success "fail to attach chain_attach_cgroup_1" \
    bfcli chain attach --name chain_attach_cgroup_1 --option cgpath=/sys/fs/cgroup/user.slice
expect_failure "pings from host to netns are blocked by cgroup chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_cgroup_0" \
    bfcli chain flush --name chain_attach_cgroup_0
expect_success "flush chain_attach_cgroup_1" \
    bfcli chain flush --name chain_attach_cgroup_1
# Netfilter
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_nf_0" \
    bfcli chain load --from-str \"chain chain_attach_nf_0 BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_nf_1" \
    bfcli chain load --from-str \"chain chain_attach_nf_1 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "attach chain_attach_nf_0" \
    bfcli chain attach --name chain_attach_nf_0 --option family=inet4 --option priorities=101-102
expect_failure "fail to attach chain_attach_nf_1" \
    bfcli chain attach --name chain_attach_nf_1 --option family=inet4 --option priorities=101-102
expect_failure "pings from host to netns are blocked by Netfilter chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_nf_0" \
    bfcli chain flush --name chain_attach_nf_0
expect_success "flush chain_attach_nf_1" \
    bfcli chain flush --name chain_attach_nf_1

log "[SUITE] chain update"
# Failures
expect_failure "no chain defined in --from-str" \
    bfcli chain update --from-str \"\"
expect_failure "invalid --name" \
    bfcli chain update --name invalid_name --from-str \"chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_failure "--name does not refer to an existing chain" \
    bfcli chain update --name chain_load_xdp_1 --from-str \"chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, do not attach" \
    bfcli chain set --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
expect_success "chain to update is not attached" \
    bfcli chain update --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
# Chain exist and is attached
expect_success "define chain to update" \
    bfcli chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT\"
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "update chain, new chain has no hook options" \
    bfcli chain update --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP\"
expect_failure "pings from host to netns are blocked" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "update chain, new chain has hook options (which are ignored)" \
    bfcli chain update --name chain_load_xdp_3 --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT\"
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_load_xdp_3" \
    bfcli chain flush --name chain_load_xdp_3


################################################################################
#
# Cleanup
#
################################################################################

kill $BPFILTER_PID
exit 0
