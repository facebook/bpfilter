#!/usr/bin/env bash

set -e

WORKDIR=$(mktemp -d)
BF_OUTPUT_FILE=${WORKDIR}/bf.log
NS_OUTPUT_FILE=${WORKDIR}/ns.log
BPFILTER_BPFFS_PATH=/tmp/bpffs
BPFILTER_PID=
SETUSERNS_SOCKET_PATH=${WORKDIR}/setuserns.sock

HAS_TOKEN_SUPPORT=0

# Network settings
NETNS_NAME="bftestns"
VETH_HOST="veth_host"
VETH_NS="veth_ns"
HOST_IP="10.0.0.1/24"
NS_IP="10.0.0.2/24"
HOST_IP_ADDR="10.0.0.1"
NS_IP_ADDR="10.0.0.2"
HOST_IFINDEX=
NS_IFINDEX=

# Tested binaries
BFCLI=
_BPFILTER= # bpfilter binary path
BPFILTER= # bpfilter command to use in tests (includes the required options)
SETUSERNS=

# Colors
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


################################################################################
#
# Options
#
################################################################################

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
            _BPFILTER=$(realpath $2)
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
# Setup
#
################################################################################

setup() {
    # Disable selinux if available, not all distros enforce setlinux
    if command -v setenforce &> /dev/null; then
        setenforce 0
    fi

    # Check if BPF token is supported
    bash -c "sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -q \"__s32 prog_token_fd;\"" && HAS_TOKEN_SUPPORT=1 || HAS_TOKEN_SUPPORT=0

    # Create the namespaces mount points
    mkdir ${WORKDIR}/ns
    mount --bind ${WORKDIR}/ns ${WORKDIR}/ns
    mount --make-private ${WORKDIR}/ns

    touch ${WORKDIR}/ns/{user,mnt}

    # Create the netns to be used by unshare
    ip netns add ${NETNS_NAME}

    # Create the user and mount namespaces, mount a new /run to have the bpfilter socket
    if [ $HAS_TOKEN_SUPPORT -eq 1 ]; then
        ${SETUSERNS} out --socket ${SETUSERNS_SOCKET_PATH} &
        SETUSERNS_PID=$!

        unshare \
            --user=${WORKDIR}/ns/user \
            --mount=${WORKDIR}/ns/mnt \
            --net=/var/run/netns/${NETNS_NAME} \
            --keep-caps \
            --map-groups=all \
            --map-users=all \
            -r /bin/bash -c "
                set -e
                mount -t tmpfs tmpfs /run
                mkdir -p ${BPFILTER_BPFFS_PATH}
                ${SETUSERNS} in --socket ${SETUSERNS_SOCKET_PATH} --bpffs-mount-path ${BPFILTER_BPFFS_PATH}
        " > "$NS_OUTPUT_FILE" 2>&1 &

        BPFILTER="${_BPFILTER} --verbose debug --with-bpf-token --bpffs-path ${BPFILTER_BPFFS_PATH}"
        wait $SETUSERNS_PID
    else
        unshare --net=/var/run/netns/${NETNS_NAME} > "$NS_OUTPUT_FILE" 2>&1 &
        BPFILTER="${_BPFILTER} --verbose debug"
    fi

    # Create the veth
    ip link add ${VETH_HOST} type veth peer name ${VETH_NS}
    ip link set ${VETH_NS} netns ${NETNS_NAME}

    # Set IP addresses
    ip addr add ${HOST_IP} dev ${VETH_HOST}
    ip netns exec ${NETNS_NAME} ip addr add ${NS_IP} dev ${VETH_NS}

    # Bring everything up
    ip link set ${VETH_HOST} up
    ip netns exec ${NETNS_NAME} ip link set ${VETH_NS} up
    ip netns exec ${NETNS_NAME} ip link set lo up

    # Log environment details
    HOST_IFINDEX=$(ip -o link show ${VETH_HOST} | awk '{print $1}' | cut -d: -f1)
    NS_IFINDEX=$(ip netns exec ${NETNS_NAME} ip -o link show ${VETH_NS} | awk '{print $1}' | cut -d: -f1)

    log "End-to-end test configuration:"
    log "${BLUE}  Workdir: ${WORKDIR}"
    log "${BLUE}  Network interfaces:"
    log "${BLUE}    ${HOST_IFINDEX}: ${VETH_HOST} @ ${HOST_IP_ADDR}"
    log "${BLUE}    ${NS_IFINDEX}: ${VETH_NS} @ ${NS_IP_ADDR}"
    log "${BLUE}  Tested binaries"
    log "${BLUE}    bfcli: ${BFCLI}"
    log "${BLUE}    bpfilter: ${_BPFILTER}"
    log "${BLUE}    setuserns: ${SETUSERNS}"
}

cleanup() {
    if [ -n "$BPFILTER_PID" ]; then
        kill $BPFILTER_PID 2>/dev/null || true
    fi

    if [ "${1:-0}" -ne 0 ] && [ -f "$NS_OUTPUT_FILE" ]; then
        echo -e "${YELLOW}[.] ${YELLOW_BOLD}namespace output:${RESET}"
        cat "$NS_OUTPUT_FILE"
    fi

    if [ "${1:-0}" -ne 0 ] && [ -f "$BF_OUTPUT_FILE" ]; then
        echo -e "${YELLOW}[.] ${YELLOW_BOLD}bpfilter output:${RESET}"
        cat "$BF_OUTPUT_FILE"
    fi

    # netns should be unmounted AND deleted
    umount /var/run/netns/${NETNS_NAME} || true
    ip netns delete ${NETNS_NAME}

    # If BPF token is not supported, user and mnt namespaces are not mounted
    if [ "${HAS_TOKEN_SUPPORT:-1}" -eq 1 ]; then
        umount ${WORKDIR}/ns/user || true
        umount ${WORKDIR}/ns/mnt || true
    fi

    umount ${WORKDIR}/ns || true

    exit ${1:-0}
}

start_daemon() {
    local timeout=2
    local start_time=$(date +%s)
    local end_time=$((start_time + timeout))

    ${FROM_NS} ${BPFILTER} > ${BF_OUTPUT_FILE} 2>&1 &
    BPFILTER_PID=$!

    # Wait for the daemon to listen to the requests
    while [ $(date +%s) -lt $end_time ]; do
        if grep -q "waiting for requests" "${BF_OUTPUT_FILE}"; then
            return 0
        fi
        sleep 0.01
    done

    return 1
}

stop_daemon() {
    if [ -n "$BPFILTER_PID" ]; then
        kill $BPFILTER_PID 2>/dev/null || true
        wait $BPFILTER_PID
    fi
}

with_daemon() {
    start_daemon
    "$@"
    stop_daemon
}

without_daemon() {
    "$@"
}

# Set trap to ensure cleanup happens
trap 'cleanup $?' EXIT
trap 'cleanup 1' INT TERM

# Configure the environment
setup


################################################################################
#
# Testing
#
################################################################################

expect_result() {
    local description="$1"
    local expected_result="$2"  # 0 = success, "non-zero" or any number for failure
    shift 2

    # Build the command string for eval
    local cmd="$*"

    # Capture both stdout and stderr
    local output
    local result=0
    output=$(eval "$cmd" 2>&1) || result=$?

    # Check if the result matches the expected result
    if { [ "$expected_result" = "0" ] && [ $result -eq 0 ]; } ||
       { [ "$expected_result" = "non-zero" ] && [ $result -ne 0 ]; } ||
       { [ "$expected_result" != "0" ] && [ "$expected_result" != "non-zero" ] && [ $result -eq "$expected_result" ]; }; then
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

        # Show expected vs actual result
        if [ "$expected_result" = "0" ]; then
            echo -e "${YELLOW}Expected exit code 0, got ${result}${RESET}" >&2
        elif [ "$expected_result" = "non-zero" ]; then
            echo -e "${YELLOW}Expected non-zero exit code, got ${result}${RESET}" >&2
        else
            echo -e "${YELLOW}Expected exit code ${expected_result}, got ${result}${RESET}" >&2
        fi
        echo >&2

        return 1
    fi
}

expect_success() {
    local description="$1"
    shift
    expect_result "$description" 0 "$@"
}

expect_failure() {
    local description="$1"
    shift
    expect_result "$description" "non-zero" "$@"
}

FROM_NS=
if [ "${HAS_TOKEN_SUPPORT:-1}" -eq 1 ]; then
    FROM_NS="nsenter --mount=${WORKDIR}/ns/mnt --user=${WORKDIR}/ns/user --net=/var/run/netns/${NETNS_NAME}"
else
    FROM_NS="nsenter --net=/var/run/netns/${NETNS_NAME}"
fi

WITH_TIMEOUT="timeout --signal INT --preserve-status .5"


################################################################################
#
# Run tests
#
################################################################################

suite_netns_to_host() {
    log "[SUITE] netns: netns -> host"
    expect_failure "can't attach chain to host iface from netns" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
    expect_success "can ping host iface from netns" \
        ${FROM_NS} ping -c 1 -W 0.25 ${HOST_IP_ADDR}
    expect_success "attach chain to ns iface" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
    expect_failure "can't ping ns iface from host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked on ingress" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/ip4\.proto eq 0x01/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_netns_to_host

suite_host_to_netns() {
    log "[SUITE] netns: host -> netns"
    expect_failure "can't attach chain to host iface from netns" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
    expect_success "can ping the netns iface from the host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "attach chain to the netns iface" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
    expect_failure "can't ping the netns iface from the host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked on ingress" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/ip4\.proto eq 0x01/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_host_to_netns

suite_icmp_TC() {
    log "[SUITE] icmp: block by TC"
    expect_success "can ping the netns iface from the host" \
        ${FROM_NS} ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "attach chain to ns iface" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmp.type eq 8 icmp.code eq 0 counter DROP\"
    expect_failure "can't ping ns iface from host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked by TC chain" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/icmp\.code eq 0x00/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_icmp_TC

suite_icmp_XDP() {
    log "[SUITE] icmp: block by XDP"
    expect_success "can ping the netns iface from the host" \
        ${FROM_NS} ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "attach chain to ns iface" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmp.type eq 8 icmp.code eq 0 counter DROP\"
    expect_failure "can't ping the netns iface from the host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked by XDP chain" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/icmp\.code eq 0x00/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_icmp_XDP

suite_ip4() {
    log "[SUITE] ip4: parse matchers"
    expect_success "ip4.snet in" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP ACCEPT rule ip4.snet in {192.168.1.14/24,10.211.0.0/16} DROP\"
    expect_success "ip4.dnet in" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP ACCEPT rule ip4.dnet in {192.168.1.14/24,10.211.0.0/16} DROP\"
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_ip4

suite_ip6() {
    log "[SUITE] ip6: parse matchers"
    expect_success "ip6.snet in" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP ACCEPT rule ip6.snet in {fdb2:2c26:f4e4:0:21c:42ff:fe09:1a95/64,fe80::21c:42ff:fe09:1a95/64} DROP\"
    expect_success "ip6.dnet in" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP ACCEPT rule ip6.dnet in {fdb2:2c26:f4e4:0:21c:42ff:fe09:1a95/64,fe80::21c:42ff:fe09:1a95/64} DROP\"
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_ip6

suite_icmpv6_chain_set() {
    log "[SUITE] icmpv6: chain set"
    expect_success "can parse icmpv6 type and code by TC chain" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmpv6.type eq 128 icmpv6.code eq 0 counter DROP\"
    expect_success "can parse icmpv6 type and code by TC chain" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmp.type eq 8 icmp.code eq 0 counter DROP\"
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_icmpv6_chain_set

suite_chain_set() {
    log "[SUITE] chain: set"
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
}
with_daemon suite_chain_set

suite_chain_load() {
    log "[SUITE] chain: load"
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
}
with_daemon suite_chain_load

suite_chain_attach() {
    log "[SUITE] chain: attach"
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
}
with_daemon suite_chain_attach

suite_chain_update() {
    log "[SUITE] chain: update"
    # Failures
    expect_failure "no chain defined in --from-str" \
        ${FROM_NS} ${BFCLI} chain update --from-str \"\"
    expect_failure "invalid --name" \
        ${FROM_NS} ${BFCLI} chain update --name invalid_name --from-str \"chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT\"
    expect_failure "--name does not refer to an existing chain" \
        ${FROM_NS} ${BFCLI} chain update --name chain_load_xdp_1 --from-str \"chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT\"
    expect_success "single chain defined in --from-str, do not attach" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
    expect_failure "chain to update is not attached" \
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
}
with_daemon suite_chain_update

suite_ruleset() {
    log "[SUITE] ruleset: set/get/flush"
    expect_success "ruleset set" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain ruleset_set_xdp_0 BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT chain ruleset_set_xdp_1 BF_HOOK_XDP DROP chain ruleset_set_tc_0 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=103-104\} ACCEPT\"
    expect_success "flush chain ruleset_set_xdp_0" \
        ${FROM_NS} ${BFCLI} chain flush --name ruleset_set_xdp_0
    expect_success "ruleset get" \
        ${FROM_NS} ${BFCLI} ruleset get
    expect_success "replace ruleset" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain ruleset_set_xdp_0 BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT chain ruleset_set_xdp_1 BF_HOOK_XDP DROP chain ruleset_set_tc_0 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=103-104\} ACCEPT\"
    expect_success "ruleset flush" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_ruleset

suite_daemon_already_running() {
    log "[SUITE] daemon: daemon is already running"
    expect_failure "start the daemon" \
        ${FROM_NS} ${WITH_TIMEOUT} ${BPFILTER}
}
with_daemon suite_daemon_already_running

suite_daemon_existing_sock() {
    log "[SUITE] daemon: handle existing daemon and leftover socket"
    expect_success "create a fake socket file" \
        ${FROM_NS} touch /run/bpfilter/daemon.sock
    expect_success "socket file exists, but no daemon running" \
        ${FROM_NS} ${WITH_TIMEOUT} ${BPFILTER}
}
without_daemon suite_daemon_existing_sock

suite_daemon_restore_non_attached() {
    log "[SUITE] daemon: restore non-attached programs"

    start_daemon
        expect_success "create a chain, do not attach it" \
            ${FROM_NS} ${BFCLI} chain set --from-str \"chain test_chain BF_HOOK_XDP ACCEPT\"
    stop_daemon

    start_daemon
        expect_success "attach the restored chain" \
            ${FROM_NS} ${BFCLI} chain attach --name test_chain --option ifindex=${NS_IFINDEX}
    stop_daemon
}
without_daemon suite_daemon_restore_non_attached


################################################################################
#
# Cleanup
#
################################################################################

exit 0
