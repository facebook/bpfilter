#!/usr/bin/env bash

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
BPFILTER_PID=

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
# Options
#
################################################################################

BFCLI=
BPFILTER=
SETUSERNS=

# Function to display usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --bfcli PATH      Path to bfcli executable"
    echo "  --bpfilter PATH   Path to bpfilter executable"
    echo "  --setuserns PATH  Path to the tool used to setup the user namespace"
    echo "  -h, --help        Display this help message and exit"
    exit 1
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bfcli)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --bfcli requires a path argument."
                usage
            fi
            BFCLI=$(realpath $2)
            shift 2
            ;;
        --bpfilter)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --bpfilter requires a path argument."
                usage
            fi
            BPFILTER=$(realpath $2)
            shift 2
            ;;
        --setuserns)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --setuserns requires a path argument."
                usage
            fi
            SETUSERNS=$(realpath $2)
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option '$1'"
            usage
            ;;
    esac
done


################################################################################
#
# Start bpfilter
#
################################################################################

# Disable selinux if available, not all distros enforce setlinux
if command -v setenforce &> /dev/null; then
    setenforce 0
fi

BPFILTER_OUTPUT_FILE=$(mktemp)
SETUSERNS_SOCKET_PATH=$(mktemp -u)

# Check if bpf_attr has a prog_token_fd field, if not, do not run bpfilter in a
# userns.
HAS_TOKEN_SUPPORT=0
bash -c "sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -q \"__s32 prog_token_fd;\"" && HAS_TOKEN_SUPPORT=1 || HAS_TOKEN_SUPPORT=0

if [ $HAS_TOKEN_SUPPORT -eq 1 ]; then
    log "starting bpfilter with BPF token"
    ${SETUSERNS} out --socket ${SETUSERNS_SOCKET_PATH} &

    unshare --user --mount --net --keep-caps --map-groups=all --map-users=all -r /bin/bash -c "
        ${SETUSERNS} in --socket ${SETUSERNS_SOCKET_PATH}
        ${BPFILTER} --transient --verbose debug --verbose bpf --with-bpf-token
    " > "$BPFILTER_OUTPUT_FILE" 2>&1 &
else
    log "starting bpfilter without BPF token"
    unshare --net /bin/bash -c "
        ${BPFILTER} --transient --verbose debug --verbose bpf
    " > "$BPFILTER_OUTPUT_FILE" 2>&1 &
fi

# Wait for bpfilter to initialize
sleep 0.25

BPFILTER_PID=$(pgrep bpfilter)
log "bpfilter PID is ${BPFILTER_PID}"

ip netns attach ${NAMESPACE} ${BPFILTER_PID}
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
    ping -c 1 ${NS_IP_ADDR}

FROM_NS="nsenter --all --target ${BPFILTER_PID}"

################################################################################
#
# Run tests
#
################################################################################

log "[SUITE] netns: define chains from ns"
expect_failure "can't attach chain to host iface from ns" \
    ${FROM_NS} ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "can ping host iface from netns" \
    ${FROM_NS} ping -c 1 -W 0.25 ${HOST_IP_ADDR}
expect_success "attach chain to ns iface" \
    ${FROM_NS} ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
expect_failure "can't ping ns iface from host" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "pings have been blocked on ingress" \
    ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/ip4\.proto eq 0x01/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
expect_success "flushing the ruleset" \
    ${FROM_NS} ${BFCLI} ruleset flush

log "[SUITE] Define chain from the netns"
expect_failure "can't attach chain to host iface from netns" \
    ${FROM_NS} ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "can ping the netns iface from the host" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "attach chain to the netns iface" \
    ${FROM_NS} ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
expect_failure "can't ping the netns iface from the host" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "pings have been blocked on ingress" \
    ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/ip4\.proto eq 0x01/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
expect_success "flushing the ruleset" \
    ${FROM_NS} ${BFCLI} ruleset flush

log "[SUITE] netns: define chains from the netns"
expect_failure "no chain defined in --from-str" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"\"
expect_failure "multiple chains defined in --from-str, no --name" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT\"
expect_failure "multiple chains defined in --from-str, --name does not exist" \
    ${FROM_NS} ${BFCLI} chain set --name invalid --from-str \"chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, do not attach" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_set_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, attach" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_set_xdp_1 BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT\"
expect_success "multiple chains defined in --from-str, do not attach" \
    ${FROM_NS} ${BFCLI} chain set --name chain_set_tc_0 --from-str \"chain chain_set_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_set_tc_1 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "multiple chains defined in --from-str, attach" \
    ${FROM_NS} ${BFCLI} chain set --name chain_set_tc_2 --from-str \"chain chain_set_tc_2 BF_HOOK_TC_EGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT chain chain_set_tc_3 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "replace a chain that is not attached, do not attach the new one" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_set_xdp_0 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "replace a chain that is not attached, attach the new one" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_set_tc_0 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=101-102\} ACCEPT\"
expect_success "replace a chain that is attached, do not attach the new one" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_set_xdp_1 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "replace a chain that is attached, attach the new one" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_set_tc_2 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=103-104\} ACCEPT\"
expect_success "flush chain_set_xdp_0" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_set_xdp_0
expect_success "flush chain_set_xdp_1" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_set_xdp_1
expect_success "flush chain_set_tc_0" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_set_tc_0
expect_success "flush chain_set_tc_2" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_set_tc_2
expect_failure "ensure removed chain can't be fetched" \
    ${FROM_NS} ${BFCLI} chain get --name chain_set_tc_2

log "[SUITE] chain load"
# No chain found
expect_failure "no chain defined in --from-str" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"\"
# Single chain found
expect_failure "single chain defined in --from-str, invalid --name" \
    ${FROM_NS} ${BFCLI} chain load --name invalid_name --from-str \"chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, no --name" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, select with valid --name" \
    ${FROM_NS} ${BFCLI} chain load --name chain_load_xdp_2 --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
expect_success "get chain_load_xdp_1" \
    ${FROM_NS} ${BFCLI} chain get --name chain_load_xdp_1
expect_success "get chain_load_xdp_2" \
    ${FROM_NS} ${BFCLI} chain get --name chain_load_xdp_2
expect_success "flush chain_load_xdp_1" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_load_xdp_1
expect_success "flush chain_load_xdp_2" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_load_xdp_2
# Multiple chains found
expect_failure "multiple chains defined in --from-str, no --name" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_load_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_1 BF_HOOK_TC_INGRESS ACCEPT\"
expect_failure "multiple chains defined in --from-str, invalid --name" \
    ${FROM_NS} ${BFCLI} chain load --name invalid --from-str \"chain chain_load_tc_2 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_3 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "multiple chains defined in --from-str, valid --name" \
    ${FROM_NS} ${BFCLI} chain load --name chain_load_tc_4 --from-str \"chain chain_load_tc_4 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_5 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "get chain_load_tc_4" \
    ${FROM_NS} ${BFCLI} chain get --name chain_load_tc_4
expect_success "flush chain_load_tc_4" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_load_tc_4

log "[SUITE] chain attach"
# Failures
expect_success "load an XDP chain" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_0 BF_HOOK_XDP ACCEPT\"
expect_failure "fail to attach with unsupported options" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_0 --option family=inet4 --option priorities=101-102
expect_success "ensure hasn't been unloaded" \
    ${FROM_NS} ${BFCLI} chain get --name chain_attach_0
expect_success "flush the chain" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_0
# XDP
expect_success "ping from host to netns is accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_xdp_0" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_xdp_0 BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_xdp_1" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "attach chain_attach_xdp_0" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_xdp_0 --option ifindex=${NS_IFINDEX}
expect_failure "fails to attach chain_attach_xdp_1" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_xdp_1 --option ifindex=${NS_IFINDEX}
expect_failure "pings from host to netns are blocked by XDP chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_xdp_0" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_xdp_0
expect_success "flush chain_attach_xdp_1" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_xdp_1
# TC
expect_success "ping from host to netns is accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_tc_0" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_tc_0 BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_tc_1" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_tc_1 BF_HOOK_TC_EGRESS ACCEPT\"
expect_success "attach chain_attach_tc_0" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_tc_0 --option ifindex=${NS_IFINDEX}
expect_success "attach chain_attach_tc_1" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_tc_1 --option ifindex=${NS_IFINDEX}
expect_failure "pings from host to netns are blocked by TC chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_tc_0" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_tc_0
expect_success "flush chain_attach_tc_1" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_tc_1
# cgroup
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_cgroup_0" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_cgroup_0 BF_HOOK_CGROUP_INGRESS ACCEPT\"
expect_success "load chain_attach_cgroup_1" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_cgroup_1 BF_HOOK_CGROUP_INGRESS ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "attach chain_attach_cgroup_0" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_cgroup_0 --option cgpath=/sys/fs/cgroup
expect_success "fail to attach chain_attach_cgroup_1" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_cgroup_1 --option cgpath=/sys/fs/cgroup
expect_failure "pings from host to netns are blocked by cgroup chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_cgroup_0" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_cgroup_0
expect_success "flush chain_attach_cgroup_1" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_cgroup_1
# Netfilter
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_nf_0" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_nf_0 BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_nf_1" \
    ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_nf_1 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "attach chain_attach_nf_0" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_nf_0 --option family=inet4 --option priorities=101-102
expect_failure "fail to attach chain_attach_nf_1" \
    ${FROM_NS} ${BFCLI} chain attach --name chain_attach_nf_1 --option family=inet4 --option priorities=101-102
expect_failure "pings from host to netns are blocked by Netfilter chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_nf_0" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_nf_0
expect_success "flush chain_attach_nf_1" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_attach_nf_1

log "[SUITE] chain update"
# Failures
expect_failure "no chain defined in --from-str" \
    ${FROM_NS} ${BFCLI} chain update --from-str \"\"
expect_failure "invalid --name" \
    ${FROM_NS} ${BFCLI} chain update --name invalid_name --from-str \"chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_failure "--name does not refer to an existing chain" \
    ${FROM_NS} ${BFCLI} chain update --name chain_load_xdp_1 --from-str \"chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, do not attach" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
expect_success "chain to update is not attached" \
    ${FROM_NS} ${BFCLI} chain update --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
# Chain exist and is attached
expect_success "define chain to update" \
    ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT\"
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "update chain, new chain has no hook options" \
    ${FROM_NS} ${BFCLI} chain update --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP\"
expect_failure "pings from host to netns are blocked" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "update chain, new chain has hook options (which are ignored)" \
    ${FROM_NS} ${BFCLI} chain update --name chain_load_xdp_3 --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT\"
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_load_xdp_3" \
    ${FROM_NS} ${BFCLI} chain flush --name chain_load_xdp_3


################################################################################
#
# Cleanup
#
################################################################################

kill $BPFILTER_PID
exit 0
