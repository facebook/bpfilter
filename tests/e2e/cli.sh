#!/usr/bin/env bash

set -e

WORKDIR=$(mktemp -d)
BF_OUTPUT_FILE=${WORKDIR}/bf.log
NS_OUTPUT_FILE=${WORKDIR}/ns.log
BPFILTER_BPFFS_PATH=/tmp/bpffs
BPFILTER_PID=
SETUSERNS_SOCKET_PATH=${WORKDIR}/setuserns.sock

EARLY_EXIT=0
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
RULESETS_DIR=

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
    echo "  --bfcli PATH        Path to bfcli executable"
    echo "  --bpfilter PATH     Path to bpfilter executable"
    echo "  --setuserns PATH    Path to the tool used to setup the user namespace"
    echo "  --rulesets-dir PATH Path to the directory containing the test rulesets"
    echo "  --early-exit        Exit immediately on first test failure"
    echo "  -h, --help          Display this help message and exit"
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
        --rulesets-dir)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --rulesets-dir requires a path argument."
                usage
            fi
            RULESETS_DIR=$(realpath $2)
            shift 2
            ;;
        --early-exit)
            EARLY_EXIT=1
            shift
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
        setenforce 0 || true
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
    log "${BLUE}    rulesets-dir: ${RULESETS_DIR}"
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

    # Use RETURN_VALUE when $1 is 0 or unset
    if [ -z "$1" ] || [ "$1" -eq 0 ]; then
        exit_code=$RETURN_VALUE
    else
        exit_code=$1
    fi

    exit $exit_code
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

RETURN_VALUE=0

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

        echo >&2

        # Show expected vs actual result
        if [ "$expected_result" = "0" ]; then
            echo -e "${RED_BOLD}bfcli exited with ${result}, expected 0${RESET}" >&2
        elif [ "$expected_result" = "non-zero" ]; then
            echo -e "${RED_BOLD}bfcli exited with ${result}, expected non-zero${RESET}" >&2
        else
            echo -e "${RED_BOLD}bfcli exited with ${result}, expected ${expected_result}${RESET}" >&2
        fi

        # Print the command that was executed
        echo -e "${YELLOW}Command:${RESET} $cmd" >&2

        # Print the captured output
        echo -e "${YELLOW}Output:${RESET}" >&2
        echo "$output" >&2
        echo >&2

        if ! kill -0 "$BPFILTER_PID" 2>/dev/null; then
            echo -e "${RED_BOLD}bpfilter crashed${RESET}"
            return 1
        fi

        # If early exit is enabled, exit immediately
        if [ "$EARLY_EXIT" -eq 1 ]; then
            echo -e "${RED_BOLD}Early exit requested, stopping tests${RESET}" >&2
            return 1
        fi

        # Ensure that if we don't stop right now, we'll return an error code
        # when the test ends.
        RETURN_VALUE=1

        return 0
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

expect_ruleset_ok() {
    local ruleset="$1"

    CHAIN="chain xdp BF_HOOK_XDP ACCEPT ${ruleset}"

    expect_success "valid ruleset '${ruleset}'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"${CHAIN}\"
}

expect_ruleset_nok() {
    local ruleset="$1"

    CHAIN="chain xdp BF_HOOK_XDP ACCEPT ${ruleset}"

    expect_failure "invalid ruleset '${ruleset}'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"${CHAIN}\"
}

expect_matcher_ok() {
    local matcher="$1"

    CHAIN="chain xdp BF_HOOK_XDP ACCEPT rule ${matcher} counter DROP"

    expect_success "valid matcher '${matcher}'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"${CHAIN}\"
}

expect_matcher_nok() {
    local matcher="$1"

    CHAIN="chain xdp BF_HOOK_XDP ACCEPT rule ${matcher} counter DROP"

    expect_failure "invalid matcher '${matcher}'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"${CHAIN}\"
}


################################################################################
#
# Run tests
#
################################################################################

suite_netns_to_host() {
    log "[SUITE] netns: netns -> host"
    expect_failure "can't attach chain to host iface from netns" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp log link,transport counter DROP\"
    expect_success "can ping host iface from netns" \
        ${FROM_NS} ping -c 1 -W 0.25 ${HOST_IP_ADDR}
    expect_success "attach chain to ns iface" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp log link,internet counter DROP\"
    expect_failure "can't ping ns iface from host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked on ingress" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/log link,internet/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_netns_to_host

suite_bcli_options_error() {
    log "[SUITE] bfcli: options error"
    expect_failure "ruleset set: --from-str and --from-file are incompatible" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"\" --from-file \"\"
    expect_failure "ruleset set: --from-str or --from-file are required" \
        ${FROM_NS} ${BFCLI} ruleset set

    expect_failure "chain set: --from-str and --from-file are incompatible" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"\" --from-file \"\"
    expect_failure "chain set: --from-str or --from-file are required" \
        ${FROM_NS} ${BFCLI} chain set

    expect_failure "chain get: --name is required" \
        ${FROM_NS} ${BFCLI} chain get

    expect_failure "chain logs: --name is required" \
        ${FROM_NS} ${BFCLI} chain logs

    expect_failure "chain load: --from-str and --from-file are incompatible" \
        ${FROM_NS} ${BFCLI} chain load --from-str \"\" --from-file \"\"
    expect_failure "chain load: --from-str or --from-file are required" \
        ${FROM_NS} ${BFCLI} chain load

    expect_failure "chain attach: --name is required" \
        ${FROM_NS} ${BFCLI} chain attach

    expect_failure "chain attach: --from-str and --from-file are incompatible" \
        ${FROM_NS} ${BFCLI} chain attach --from-str \"\" --from-file \"\"
    expect_failure "chain attach: --from-str or --from-file are required" \
        ${FROM_NS} ${BFCLI} chain attach

    expect_failure "chain flush: --name is required" \
        ${FROM_NS} ${BFCLI} chain flush
}
with_daemon suite_bcli_options_error

suite_host_to_netns() {
    log "[SUITE] netns: host -> netns"
    expect_failure "can't attach chain to host iface from netns" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp log link counter DROP\"
    expect_success "can ping the netns iface from the host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "attach chain to the netns iface" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
    expect_failure "can't ping the netns iface from the host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked on ingress" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/ip4\.proto eq icmp/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_host_to_netns

suite_icmp_TC() {
    log "[SUITE] icmp: block by TC"
    expect_success "can ping the netns iface from the host" \
        ${FROM_NS} ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "attach chain to ns iface" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmp.type eq echo-request icmp.code eq 0 counter DROP\"
    expect_failure "can't ping ns iface from host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked by TC chain" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/icmp\.code eq 0/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_icmp_TC

suite_icmp_XDP() {
    log "[SUITE] icmp: block by XDP"
    expect_success "can ping the netns iface from the host" \
        ${FROM_NS} ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "attach chain to ns iface" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmp.type eq echo-request icmp.code eq 0 log transport,internet counter DROP\"
    expect_failure "can't ping the netns iface from the host" \
        ping -c 1 -W 0.25 ${NS_IP_ADDR}
    expect_success "pings have been blocked by XDP chain" \
        ${FROM_NS} ${BFCLI} chain get --name xdp \| awk \'/log internet,transport/{getline\; print \$2}\' \| grep -q \"^1$\" \&\& exit 0 \|\| exit 1
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_icmp_XDP

suite_icmpv6_chain_set() {
    log "[SUITE] icmpv6: chain set"
    expect_success "can parse icmpv6 type and code by TC chain" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmpv6.type eq echo-request icmpv6.code eq 0 log internet counter DROP\"
    expect_success "can parse icmpv6 type and code by TC chain" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule icmp.type eq echo-request icmp.code eq 0 log internet,link counter DROP\"
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_icmpv6_chain_set

suite_ipv6_nexthdr_chain_set() {
    log "[SUITE] ipv6 next-header: chain set"
    expect_success "can parse ipv6 next-header by TC chain" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip6.nexthdr eq hop log internet counter DROP\"
    expect_success "can parse ipv6 next-header by XDP chain" \
	    ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip6.nexthdr not tcp log transport counter DROP\"
    expect_success "flushing the ruleset" \
        ${FROM_NS} ${BFCLI} ruleset flush
}
with_daemon suite_ipv6_nexthdr_chain_set

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
        ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_xdp_0 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,transport,internet counter DROP\"
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
        ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_tc_0 BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto icmp log internet,link,transport counter DROP\"
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
        ${FROM_NS} ${BFCLI} chain load --from-str \"chain chain_attach_cgroup_1 BF_HOOK_CGROUP_INGRESS ACCEPT rule ip4.proto icmp log internet counter DROP\"
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
        ${FROM_NS} ${BFCLI} chain update --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log transport counter DROP\"
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

suite_daemon_pin_updated_chain() {
    log "[SUITE] daemon: check if updated chain is pinned"

    start_daemon
        expect_success "create a chain and attach it" \
            ${FROM_NS} ${BFCLI} chain set --from-str \"chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT\"
        expect_success "can ping the netns iface from the host" \
            ${FROM_NS} ping -c 1 -W 0.25 ${NS_IP_ADDR}
        expect_success "after set the first chain, bpfilter only has a single BPF program" \
            ${FROM_NS} ${BFCLI} ruleset get \| grep "^chain" \| awk 'END{exit\ NR!=1}'
        expect_success "after set the first chain, bpftool only has a single bf_prog BPF program" \
            bpftool prog \| grep \"name bf_prog\" \| awk 'END{exit\ NR!=1}'

        expect_success "create a chain and attach it" \
            ${FROM_NS} ${BFCLI} chain update --from-str \"chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule meta.l4_proto eq icmp DROP\"
        expect_failure "can't ping the netns iface from the host" \
            ping -c 1 -W 0.25 ${NS_IP_ADDR}
        expect_success "after updating the chain, bpfilter only has a single BPF program" \
            ${FROM_NS} ${BFCLI} ruleset get \| grep "^chain" \| awk 'END{exit\ NR!=1}'
        expect_success "after updating the chain, bpftool only has a single bf_prog BPF program" \
            bpftool prog \| grep \"name bf_prog\" \| awk 'END{exit\ NR!=1}'
    stop_daemon

    start_daemon
        expect_success "after restarting the daemon, bpfilter only has a single BPF program" \
            ${FROM_NS} ${BFCLI} ruleset get \| grep "^chain" \| awk 'END{exit\ NR!=1}'
        expect_success "after restarting the daemon, bpftool only has a single bf_prog BPF program" \
            bpftool prog \| grep \"name bf_prog\" \| awk 'END{exit\ NR!=1}'
    stop_daemon
}
without_daemon suite_daemon_pin_updated_chain

suite_rule_meta_order() {
    log "[SUITE] cli: allow out of order log, counter"
    expect_failure "duplicate keyword counter" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter counter DROP\"
    expect_failure "duplicate keyword log" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter log link log link DROP\"
    expect_success "none of log, counter" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp DROP\"
    expect_success "only log" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link DROP\"
    expect_success "only counter" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP\"
    expect_success "use log then counter" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link counter DROP\"
    expect_success "use counter then log" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain order BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter log link DROP\"
}
with_daemon suite_rule_meta_order

suite_log() {
    log "[SUITE] cli: log"
    expect_failure "invalid log action" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log counter DROP\"
    expect_failure "invalid log header" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log ip counter DROP\"
    expect_success "single header" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link counter DROP\"
    expect_success "multiple headers #1" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,internet counter DROP\"
    expect_success "multiple headers #2" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,transport counter DROP\"
    expect_success "multiple headers out of order" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log internet,link counter DROP\"
}
with_daemon suite_log

suite_mark() {
    log "[SUITE] cli: mark"
    expect_failure "incompatible chain (XDP)" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_XDP ACCEPT rule ip4.proto icmp mark 0x16 DROP\"
    expect_failure "incompatible chain (Netfilter)" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp mark 0x16 DROP\"
    expect_failure "missing mark value" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark DROP\"
    expect_failure "invalid mark value (can't parse)" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 0x14aw DROP\"
    expect_failure "invalid mark value (negative value)" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark -3 DROP\"
    expect_failure "invalid mark value (value too big)" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 0xffffffffff DROP\"

    expect_success "valid decimal value" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 14 DROP\"
    expect_success "valid hexadecimal value" \
        ${FROM_NS} ${BFCLI} chain set --from-str \"chain xdp_mark BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp mark 0x14 DROP\"
}
with_daemon suite_mark

suite_matcher_set() {
    log "[SUITE] matcher: set"
    expect_matcher_ok "(ip4.saddr, icmp.code) in {192.168.1.1,41; 192.168.1.1,42}"
    expect_matcher_ok "(ip4.saddr, icmp.code) in {192.168.1.1 ,41; 192.168.1.1,42}"
    expect_matcher_ok "(ip4.saddr, icmp.code) in {192.168.1.1, 41; 192.168.1.1,42}"
    expect_matcher_ok "(ip4.saddr, icmp.code) in {192.168.1.1,41;192.168.1.1,42}"
    expect_matcher_ok "(ip4.saddr, icmp.code) in {
        192.168.1.1 , 41;
        192.168.1.1,42
    }"
    expect_matcher_ok "(ip6.saddr) in {
        ::1;
        ::2
    }"
    expect_matcher_ok "(ip6.snet) in {
        ::1/100;
        ::2/89
    }"
    expect_matcher_ok "(ip4.saddr, icmp.code) in {
        192.168.1.1 , 41 ;
        192.168.1.1 , 42 ;
    }"

    # Testing all the matchers
    expect_matcher_ok "(ip4.saddr, ip4.daddr) in {
        192.168.1.1, 192.168.1.2;
        192.168.1.3, 192.168.1.4
    }"
    expect_matcher_ok "(ip4.proto, ip6.nexthdr) in {6, 40; 40, 6}"
    expect_matcher_ok "(ip6.saddr, ip6.daddr) in {
        ::1, ::2;
        ::3, ::4
    }"
    expect_matcher_ok "(icmp.code, icmp.type) in {
        3, echo-reply;
        2, echo-request
    }"
    expect_matcher_ok "(icmpv6.code, icmpv6.type) in {
        3, echo-reply;
        2, echo-request
    }"
    expect_matcher_ok "(icmpv6.code, icmpv6.type   ) in {
        3, echo-reply;
        2, echo-request
    }"
    expect_matcher_ok "(icmpv6.code   , icmpv6.type   ) in {
        3, echo-reply;
        2, echo-request
    }"
    expect_matcher_ok "(  icmpv6.code,      icmpv6.type   ) in {
        3, echo-reply;
        2, echo-request
    }"

    expect_matcher_nok "(ip4.snet, ip4.dnet) in {
        192.168.1.1/24, 192.167.1.1/24;
        10.211.55.2/24, 192.168.1.1/24
    }"
    expect_matcher_nok "(ip6.snet, ip6.dnet) in {
        ::1/32, ::2/64;
        ::3/96, ::4/128
    }"
    expect_matcher_nok "(ip4.saddr, ) in {192.168.1.1,41; 192.168.1.1,42}"
    expect_matcher_nok "(ip4.saddr, icmp.code) in {192.168.1.1,41 192.168.1.1,42}"
    expect_matcher_nok "(ip4.saddr, icmp.code) in {192.168.1.141; 192.168.1.1,42}"
    expect_matcher_nok "(ip4.saddr, icmp.code) in {192.168.1.1}"
    expect_matcher_nok "(ip4.saddr;icmp.code) in {192.168.1.1,41; 192.168.1.1,42}"
    expect_matcher_nok "(ip4.saddr, icmp.code) in {}"
    expect_matcher_nok "(ip4.saddr, icmp.code) in {192.168.1.,41; 192.168.1.1,42}"
    expect_matcher_nok "(ip4.saddr, icmp.code) in {192.168.1.1,cafe; 192.168.1.1,42}"
    expect_matcher_nok "(ip4.saddr, icmp.code) in {192.168.1.1,41,192.168.1.1,42}"
}
with_daemon suite_matcher_set

suite_matcher_named_set() {
    log "[SUITE] matcher: named set"
    expect_ruleset_ok "
        set myset (ip4.saddr) in {
            192.168.1.1;
            192.168.1.2
        }
        rule
            (ip4.saddr) in myset
            counter
            ACCEPT
    "
    expect_ruleset_ok "
        set myset (ip4.saddr, ip4.proto) in {
            192.168.1.1, tcp;
            192.168.1.2, udp
        }
        rule
            (ip4.saddr, ip4.proto) in myset
            counter
            ACCEPT
    "

    expect_ruleset_nok "set myset (ip4.saddr) eq { 192.168.1.1 }"
    expect_ruleset_nok "set myset (ip4.saddr, meta.ifindex) in { 192.168.1.1 }"
    expect_ruleset_nok "set myset (ip4.saddr, ip4.proto) in { 192.168.1.1 }"
    expect_ruleset_nok "
        set myset (ip4.saddr) in { 192.168.1.1 }
        rule (ip4.daddr) in myset
    "
    expect_ruleset_nok "
        set myset (ip4.saddr) in { 192.168.1.1 }
        rule (ip4.daddr) in my_set
    "
}
with_daemon suite_matcher_named_set

suite_matcher_meta() {
    log "[SUITE] matcher: meta.iface"
    expect_matcher_ok "meta.iface eq lo"
    expect_matcher_ok "meta.iface eq 1"
    expect_matcher_ok "meta.iface eq 01"
    expect_matcher_ok "meta.iface eq 4294967294"

    expect_matcher_nok "meta.iface eq 0x10"
    expect_matcher_nok "meta.iface eq -1"
    expect_matcher_nok "meta.iface eq 42949672941"
    expect_matcher_nok "meta.iface eq -2147483646"
    expect_matcher_nok "meta.iface eq -1"
    expect_matcher_nok "meta.iface eq -100"
    expect_matcher_nok "meta.iface eq 0"
    expect_matcher_nok "meta.iface eq noiface"
    expect_matcher_nok "meta.iface eq iface_name_is_too_long"

    log "[SUITE] matcher: meta.l3_proto"
    expect_matcher_ok "meta.l3_proto eq ipv4"
    expect_matcher_ok "meta.l3_proto eq IPv6"
    expect_matcher_ok "meta.l3_proto eq 0"
    expect_matcher_ok "meta.l3_proto eq 17"
    expect_matcher_ok "meta.l3_proto eq 65535"
    expect_matcher_ok "meta.l3_proto eq 0x00"
    expect_matcher_ok "meta.l3_proto eq 0x17"
    expect_matcher_ok "meta.l3_proto eq 0xffff"

    expect_matcher_nok "meta.l3_proto eq ipv65"
    expect_matcher_nok "meta.l3_proto eq thisiswaytolongforaprotocolname"
    expect_matcher_nok "meta.l3_proto eq 0xffffff"
    expect_matcher_nok "meta.l3_proto eq -154252"

    log "[SUITE] matcher: meta.l4_proto eq"
    expect_matcher_ok "meta.l4_proto eq icmp"
    expect_matcher_ok "meta.l4_proto eq ICMPv6"
    expect_matcher_ok "meta.l4_proto eq 0"
    expect_matcher_ok "meta.l4_proto eq 17"
    expect_matcher_ok "meta.l4_proto eq 255"

    expect_matcher_nok "meta.l4_proto eq ipv4"
    expect_matcher_nok "meta.l4_proto eq imcp"
    expect_matcher_nok "meta.l4_proto eq 0x342"
    expect_matcher_nok "meta.l4_proto eq -18"
    expect_matcher_nok "meta.l4_proto eq 256"

    log "[SUITE] matcher: meta.l4_proto not"
    expect_matcher_ok "meta.l4_proto not icmp"
    expect_matcher_ok "meta.l4_proto not ICMPv6"
    expect_matcher_ok "meta.l4_proto not 0"
    expect_matcher_ok "meta.l4_proto not 17"
    expect_matcher_ok "meta.l4_proto not 255"

    expect_matcher_nok "meta.l4_proto not ipv4"
    expect_matcher_nok "meta.l4_proto not imcp"
    expect_matcher_nok "meta.l4_proto not 0x342"
    expect_matcher_nok "meta.l4_proto not -18"
    expect_matcher_nok "meta.l4_proto not 256"

    log "[SUITE] matcher: meta.sport eq"
    expect_matcher_ok "meta.sport eq 0"
    expect_matcher_ok "meta.sport eq 40"
    expect_matcher_ok "meta.sport eq 65535"

    expect_matcher_nok "meta.sport eq -40"
    expect_matcher_nok "meta.sport eq 0x40"
    expect_matcher_nok "meta.sport eq -0x00"
    expect_matcher_nok "meta.sport eq 75000"
    expect_matcher_nok "meta.sport eq 0xffffff"
    expect_matcher_nok "meta.sport eq not_a_port"

    log "[SUITE] matcher: meta.sport not"
    expect_matcher_ok "meta.sport not 0"
    expect_matcher_ok "meta.sport not 40"
    expect_matcher_ok "meta.sport not 65535"

    expect_matcher_nok "meta.sport not -40"
    expect_matcher_nok "meta.sport not 0x40"
    expect_matcher_nok "meta.sport not -0x00"
    expect_matcher_nok "meta.sport not 75000"
    expect_matcher_nok "meta.sport not 0xffffff"
    expect_matcher_nok "meta.sport not not_a_port"

    log "[SUITE] matcher: meta.sport range"
    expect_matcher_ok "meta.sport range 0-0"
    expect_matcher_ok "meta.sport range 0-65535"
    expect_matcher_ok "meta.sport range 17-30"

    expect_matcher_nok "meta.sport range 0"
    expect_matcher_nok "meta.sport range 20-10"
    expect_matcher_nok "meta.sport range 10-20-30"
    expect_matcher_nok "meta.sport range 10000000-1000000"
    expect_matcher_nok "meta.sport range 0x20"
    expect_matcher_nok "meta.sport range 0x20-0x30"
    expect_matcher_nok "meta.sport range 0x30-0x20"
    expect_matcher_nok "meta.sport range -1-4"
    expect_matcher_nok "meta.sport range -1--4"
    expect_matcher_nok "meta.sport range not-port"
    expect_matcher_nok "meta.sport range notport"

    log "[SUITE] matcher: meta.dport eq"
    expect_matcher_ok "meta.dport eq 0"
    expect_matcher_ok "meta.dport eq 40"
    expect_matcher_ok "meta.dport eq 65535"

    expect_matcher_nok "meta.dport eq -40"
    expect_matcher_nok "meta.dport eq 0x40"
    expect_matcher_nok "meta.dport eq -0x00"
    expect_matcher_nok "meta.dport eq 75000"
    expect_matcher_nok "meta.dport eq 0xffffff"
    expect_matcher_nok "meta.dport eq not_a_port"

    log "[SUITE] matcher: meta.dport not"
    expect_matcher_ok "meta.dport not 0"
    expect_matcher_ok "meta.dport not 40"
    expect_matcher_ok "meta.dport not 65535"

    expect_matcher_nok "meta.dport not -40"
    expect_matcher_nok "meta.dport not 0x40"
    expect_matcher_nok "meta.dport not -0x00"
    expect_matcher_nok "meta.dport not 75000"
    expect_matcher_nok "meta.dport not 0xffffff"
    expect_matcher_nok "meta.dport not not_a_port"

    log "[SUITE] matcher: meta.dport range"
    expect_matcher_ok "meta.dport range 0-0"
    expect_matcher_ok "meta.dport range 0-65535"
    expect_matcher_ok "meta.dport range 17-30"

    expect_matcher_nok "meta.dport range 0"
    expect_matcher_nok "meta.dport range 20-10"
    expect_matcher_nok "meta.dport range 10-20-30"
    expect_matcher_nok "meta.dport range 10000000-1000000"
    expect_matcher_nok "meta.dport range 0x20"
    expect_matcher_nok "meta.dport range 0x20-0x30"
    expect_matcher_nok "meta.dport range 0x30-0x20"
    expect_matcher_nok "meta.dport range -1-4"
    expect_matcher_nok "meta.dport range -1--4"
    expect_matcher_nok "meta.dport range not-port"
    expect_matcher_nok "meta.dport range notport"

    log "[SUITE] matcher: meta.probability eq"
    expect_matcher_ok "meta.probability eq 0%"
    expect_matcher_ok "meta.probability eq 50%"
    expect_matcher_ok "meta.probability eq 100%"

    expect_matcher_nok "meta.probability eq 0"
    expect_matcher_nok "meta.probability eq -10%"
    expect_matcher_nok "meta.probability eq 1000"
    expect_matcher_nok "meta.probability eq 1000%"
    expect_matcher_nok "meta.probability eq 15.5%"
    expect_matcher_nok "meta.probability eq teapot"

    # Do not use expect_matcher_ok/nok as meta.mark is not compatible with XDP
    log "[SUITE] matcher: meta.mark eq"
    expect_success "valid matcher 'meta.mark eq 0'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0 counter DROP\"
    expect_success "valid matcher 'meta.mark eq 15'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 15 counter DROP\"
    expect_success "valid matcher 'meta.mark eq 0x00'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0x00 counter DROP\"
    expect_success "valid matcher 'meta.mark eq 0xffffffff'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0xffffffff counter DROP\"

    expect_failure "invalid matcher 'meta.mark eq -1'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq -1 counter DROP\"
    expect_failure "invalid matcher 'meta.mark eq 0xffffffffff'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 0xffffffffff counter DROP\"
    expect_failure "invalid matcher 'meta.mark eq 1qw'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq 1qw counter DROP\"
    expect_failure "invalid matcher 'meta.mark eq qw'" \
        ${FROM_NS} ${BFCLI} ruleset set --from-str \"chain xdp BF_HOOK_TC_INGRESS ACCEPT rule meta.mark eq qw counter DROP\"
}
with_daemon suite_matcher_meta

suite_matcher_ip4() {
    log "[SUITE] matcher: ip4.saddr eq"
    expect_matcher_ok "ip4.saddr eq 1.1.1.1"
    expect_matcher_ok "ip4.saddr eq 255.255.255.255"

    expect_matcher_nok "ip4.saddr eq notanip"
    expect_matcher_nok "ip4.saddr eq 1.1.1.1.1"
    expect_matcher_nok "ip4.saddr eq 1.1.1.1/24"
    expect_matcher_nok "ip4.saddr eq -1.1.1.1"

    log "[SUITE] matcher: ip4.saddr not"
    expect_matcher_ok "ip4.saddr not 1.1.1.1"
    expect_matcher_ok "ip4.saddr not 255.255.255.255"

    expect_matcher_nok "ip4.saddr not notanip"
    expect_matcher_nok "ip4.saddr not 1.1.1.1.1"
    expect_matcher_nok "ip4.saddr not 1.1.1.1/24"
    expect_matcher_nok "ip4.saddr not -1.1.1.1"

    log "[SUITE] matcher: ip4.daddr eq"
    expect_matcher_ok "ip4.daddr eq 1.1.1.1"
    expect_matcher_ok "ip4.daddr eq 255.255.255.255"

    expect_matcher_nok "ip4.daddr eq notanip"
    expect_matcher_nok "ip4.daddr eq 1.1.1.1.1"
    expect_matcher_nok "ip4.daddr eq 1.1.1.1/24"
    expect_matcher_nok "ip4.daddr eq -1.1.1.1"

    log "[SUITE] matcher: ip4.daddr not"
    expect_matcher_ok "ip4.daddr not 1.1.1.1"
    expect_matcher_ok "ip4.daddr not 255.255.255.255"

    expect_matcher_nok "ip4.daddr not notanip"
    expect_matcher_nok "ip4.daddr not 1.1.1.1.1"
    expect_matcher_nok "ip4.daddr not 1.1.1.1/24"
    expect_matcher_nok "ip4.daddr not -1.1.1.1"

    log "[SUITE] matcher: ip4.snet eq"
    expect_matcher_ok "ip4.snet eq 1.1.1.1/0"
    expect_matcher_ok "ip4.snet eq 1.1.1.1/17"
    expect_matcher_ok "ip4.snet eq 1.1.1.1/32"
    expect_matcher_ok "ip4.snet eq 255.255.255.255/0"
    expect_matcher_ok "ip4.snet eq 255.255.255.255/17"
    expect_matcher_ok "ip4.snet eq 255.255.255.255/32"

    expect_matcher_nok "ip4.snet eq notanip"
    expect_matcher_nok "ip4.snet eq 1.1.1.1.1"
    expect_matcher_nok "ip4.snet eq 1.1.1.1.1/"
    expect_matcher_nok "ip4.snet eq 1.1.1.1/-10"
    expect_matcher_nok "ip4.snet eq 1.1.1.1/75"
    expect_matcher_nok "ip4.snet eq 1.1.1.1/0x75"
    expect_matcher_nok "ip4.snet eq -1.1.1.1"
    expect_matcher_nok "ip4.snet eq -1.1.1.1/1"

    log "[SUITE] matcher: ip4.snet not"
    expect_matcher_ok "ip4.snet not 1.1.1.1/0"
    expect_matcher_ok "ip4.snet not 1.1.1.1/17"
    expect_matcher_ok "ip4.snet not 1.1.1.1/32"
    expect_matcher_ok "ip4.snet not 255.255.255.255/0"
    expect_matcher_ok "ip4.snet not 255.255.255.255/17"
    expect_matcher_ok "ip4.snet not 255.255.255.255/32"

    expect_matcher_nok "ip4.snet not notanip"
    expect_matcher_nok "ip4.snet not 1.1.1.1.1"
    expect_matcher_nok "ip4.snet not 1.1.1.1.1/"
    expect_matcher_nok "ip4.snet not 1.1.1.1/-10"
    expect_matcher_nok "ip4.snet not 1.1.1.1/75"
    expect_matcher_nok "ip4.snet not 1.1.1.1/0x75"
    expect_matcher_nok "ip4.snet not -1.1.1.1"
    expect_matcher_nok "ip4.snet not -1.1.1.1/1"

    log "[SUITE] matcher: ip4.dnet eq"
    expect_matcher_ok "ip4.dnet eq 1.1.1.1/0"
    expect_matcher_ok "ip4.dnet eq 1.1.1.1/17"
    expect_matcher_ok "ip4.dnet eq 1.1.1.1/32"
    expect_matcher_ok "ip4.dnet eq 255.255.255.255/0"
    expect_matcher_ok "ip4.dnet eq 255.255.255.255/17"
    expect_matcher_ok "ip4.dnet eq 255.255.255.255/32"

    expect_matcher_nok "ip4.dnet eq notanip"
    expect_matcher_nok "ip4.dnet eq 1.1.1.1.1"
    expect_matcher_nok "ip4.dnet eq 1.1.1.1.1/"
    expect_matcher_nok "ip4.dnet eq 1.1.1.1/-10"
    expect_matcher_nok "ip4.dnet eq 1.1.1.1/75"
    expect_matcher_nok "ip4.dnet eq 1.1.1.1/0x75"
    expect_matcher_nok "ip4.dnet eq -1.1.1.1"
    expect_matcher_nok "ip4.dnet eq -1.1.1.1/1"

    log "[SUITE] matcher: ip4.dnet not"
    expect_matcher_ok "ip4.dnet not 1.1.1.1/0"
    expect_matcher_ok "ip4.dnet not 1.1.1.1/17"
    expect_matcher_ok "ip4.dnet not 1.1.1.1/32"
    expect_matcher_ok "ip4.dnet not 255.255.255.255/0"
    expect_matcher_ok "ip4.dnet not 255.255.255.255/17"
    expect_matcher_ok "ip4.dnet not 255.255.255.255/32"

    expect_matcher_nok "ip4.dnet not notanip"
    expect_matcher_nok "ip4.dnet not 1.1.1.1.1"
    expect_matcher_nok "ip4.dnet not 1.1.1.1.1/"
    expect_matcher_nok "ip4.dnet not 1.1.1.1/-10"
    expect_matcher_nok "ip4.dnet not 1.1.1.1/75"
    expect_matcher_nok "ip4.dnet not 1.1.1.1/0x75"
    expect_matcher_nok "ip4.dnet not -1.1.1.1"
    expect_matcher_nok "ip4.dnet not -1.1.1.1/1"

    log "[SUITE] matcher: ip4.proto"
    expect_matcher_ok "ip4.proto eq icmp"
    expect_matcher_ok "ip4.proto eq ICMPv6"
    expect_matcher_ok "ip4.proto eq 0"
    expect_matcher_ok "ip4.proto eq 17"
    expect_matcher_ok "ip4.proto eq 255"

    expect_matcher_nok "ip4.proto eq ipv4"
    expect_matcher_nok "ip4.proto eq imcp"
    expect_matcher_nok "ip4.proto eq 0x342"
    expect_matcher_nok "ip4.proto eq -18"
    expect_matcher_nok "ip4.proto eq 256"

    log "[SUITE] matcher: ip4.proto not"
    expect_matcher_ok "ip4.proto not icmp"
    expect_matcher_ok "ip4.proto not ICMPv6"
    expect_matcher_ok "ip4.proto not 0"
    expect_matcher_ok "ip4.proto not 17"
    expect_matcher_ok "ip4.proto not 255"

    expect_matcher_nok "ip4.proto not ipv4"
    expect_matcher_nok "ip4.proto not imcp"
    expect_matcher_nok "ip4.proto not 0x342"
    expect_matcher_nok "ip4.proto not -18"
    expect_matcher_nok "ip4.proto not 256"
}
with_daemon suite_matcher_ip4

suite_matcher_ip6() {
    log "[SUITE] matcher: ip6.saddr eq"
    expect_matcher_ok "ip6.saddr eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    expect_matcher_ok "ip6.saddr eq fe80:0000:0000:0000:0202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.saddr eq 2001:db8:0:0:1:0:0:1"
    expect_matcher_ok "ip6.saddr eq 2001:db8:85a3::8a2e:370:7334"
    expect_matcher_ok "ip6.saddr eq 2001:db8::1"
    expect_matcher_ok "ip6.saddr eq ::1"
    expect_matcher_ok "ip6.saddr eq ::"
    expect_matcher_ok "ip6.saddr eq 2001:db8:85a3:0:0:8a2e:370::"
    expect_matcher_ok "ip6.saddr eq fe80::202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.saddr eq ::1:0:0:0:0:0:0"
    expect_matcher_ok "ip6.saddr eq 0:0:0:0:0:0:0:1"
    expect_matcher_ok "ip6.saddr eq 2001:db8:0:0:0:0:0:0"
    expect_matcher_ok "ip6.saddr eq ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    expect_matcher_ok "ip6.saddr eq 2001:0db8:0000:0000:0000:0000:0000:0001"

    expect_matcher_nok "ip6.saddr eq notanip"
    expect_matcher_nok "ip6.saddr eq 1.1.1.1"
    expect_matcher_nok "ip6.saddr eq 2001::db8::1"
    expect_matcher_nok "ip6.saddr eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.saddr eq 2001:0db8:85g3::8a2e:370:7334"
    expect_matcher_nok "ip6.saddr eq 2001:db8:12345::1"
    expect_matcher_nok "ip6.saddr eq 2001:db8::192.168.1.1"
    expect_matcher_nok "ip6.saddr eq :2001:db8::1"
    expect_matcher_nok "ip6.saddr eq 2001::db8::"
    expect_matcher_nok "ip6.saddr eq 2001:db8::1:"

    log "[SUITE] matcher: ip6.saddr not"
    expect_matcher_ok "ip6.saddr not 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    expect_matcher_ok "ip6.saddr not fe80:0000:0000:0000:0202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.saddr not 2001:db8:0:0:1:0:0:1"
    expect_matcher_ok "ip6.saddr not 2001:db8:85a3::8a2e:370:7334"
    expect_matcher_ok "ip6.saddr not 2001:db8::1"
    expect_matcher_ok "ip6.saddr not ::1"
    expect_matcher_ok "ip6.saddr not ::"
    expect_matcher_ok "ip6.saddr not 2001:db8:85a3:0:0:8a2e:370::"
    expect_matcher_ok "ip6.saddr not fe80::202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.saddr not ::1:0:0:0:0:0:0"
    expect_matcher_ok "ip6.saddr not 0:0:0:0:0:0:0:1"
    expect_matcher_ok "ip6.saddr not 2001:db8:0:0:0:0:0:0"
    expect_matcher_ok "ip6.saddr not ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    expect_matcher_ok "ip6.saddr not 2001:0db8:0000:0000:0000:0000:0000:0001"

    expect_matcher_nok "ip6.saddr not notanip"
    expect_matcher_nok "ip6.saddr not 1.1.1.1"
    expect_matcher_nok "ip6.saddr not 2001::db8::1"
    expect_matcher_nok "ip6.saddr not 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.saddr not 2001:0db8:85g3::8a2e:370:7334"
    expect_matcher_nok "ip6.saddr not 2001:db8:12345::1"
    expect_matcher_nok "ip6.saddr not 2001:db8::192.168.1.1"
    expect_matcher_nok "ip6.saddr not :2001:db8::1"
    expect_matcher_nok "ip6.saddr not 2001::db8::"
    expect_matcher_nok "ip6.saddr not 2001:db8::1:"

    log "[SUITE] matcher: ip6.daddr eq"
    expect_matcher_ok "ip6.daddr eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    expect_matcher_ok "ip6.daddr eq fe80:0000:0000:0000:0202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.daddr eq 2001:db8:0:0:1:0:0:1"
    expect_matcher_ok "ip6.daddr eq 2001:db8:85a3::8a2e:370:7334"
    expect_matcher_ok "ip6.daddr eq 2001:db8::1"
    expect_matcher_ok "ip6.daddr eq ::1"
    expect_matcher_ok "ip6.daddr eq ::"
    expect_matcher_ok "ip6.daddr eq 2001:db8:85a3:0:0:8a2e:370::"
    expect_matcher_ok "ip6.daddr eq fe80::202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.daddr eq ::1:0:0:0:0:0:0"
    expect_matcher_ok "ip6.daddr eq 0:0:0:0:0:0:0:1"
    expect_matcher_ok "ip6.daddr eq 2001:db8:0:0:0:0:0:0"
    expect_matcher_ok "ip6.daddr eq ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    expect_matcher_ok "ip6.daddr eq 2001:0db8:0000:0000:0000:0000:0000:0001"

    expect_matcher_nok "ip6.daddr eq notanip"
    expect_matcher_nok "ip6.daddr eq 1.1.1.1"
    expect_matcher_nok "ip6.daddr eq 2001::db8::1"
    expect_matcher_nok "ip6.daddr eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.daddr eq 2001:0db8:85g3::8a2e:370:7334"
    expect_matcher_nok "ip6.daddr eq 2001:db8:12345::1"
    expect_matcher_nok "ip6.daddr eq 2001:db8::192.168.1.1"
    expect_matcher_nok "ip6.daddr eq :2001:db8::1"
    expect_matcher_nok "ip6.daddr eq 2001::db8::"
    expect_matcher_nok "ip6.daddr eq 2001:db8::1:"

    log "[SUITE] matcher: ip6.daddr not"
    expect_matcher_ok "ip6.daddr not 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    expect_matcher_ok "ip6.daddr not fe80:0000:0000:0000:0202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.daddr not 2001:db8:0:0:1:0:0:1"
    expect_matcher_ok "ip6.daddr not 2001:db8:85a3::8a2e:370:7334"
    expect_matcher_ok "ip6.daddr not 2001:db8::1"
    expect_matcher_ok "ip6.daddr not ::1"
    expect_matcher_ok "ip6.daddr not ::"
    expect_matcher_ok "ip6.daddr not 2001:db8:85a3:0:0:8a2e:370::"
    expect_matcher_ok "ip6.daddr not fe80::202:b3ff:fe1e:8329"
    expect_matcher_ok "ip6.daddr not ::1:0:0:0:0:0:0"
    expect_matcher_ok "ip6.daddr not 0:0:0:0:0:0:0:1"
    expect_matcher_ok "ip6.daddr not 2001:db8:0:0:0:0:0:0"
    expect_matcher_ok "ip6.daddr not ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    expect_matcher_ok "ip6.daddr not 2001:0db8:0000:0000:0000:0000:0000:0001"

    expect_matcher_nok "ip6.daddr not notanip"
    expect_matcher_nok "ip6.daddr not 1.1.1.1"
    expect_matcher_nok "ip6.daddr not 2001::db8::1"
    expect_matcher_nok "ip6.daddr not 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.daddr not 2001:0db8:85g3::8a2e:370:7334"
    expect_matcher_nok "ip6.daddr not 2001:db8:12345::1"
    expect_matcher_nok "ip6.daddr not 2001:db8::192.168.1.1"
    expect_matcher_nok "ip6.daddr not :2001:db8::1"
    expect_matcher_nok "ip6.daddr not 2001::db8::"
    expect_matcher_nok "ip6.daddr not 2001:db8::1:"

    log "[SUITE] matcher: ip6.snet eq"
    expect_matcher_ok "ip6.snet eq 2001:db8::/32"
    expect_matcher_ok "ip6.snet eq 2001:db8:85a3::/48"
    expect_matcher_ok "ip6.snet eq fe80::/10"
    expect_matcher_ok "ip6.snet eq 2001:db8:85a3:8d3::/64"
    expect_matcher_ok "ip6.snet eq 2001:0db8:85a3:0000::/64"
    expect_matcher_ok "ip6.snet eq 2001:db8::1/128"
    expect_matcher_ok "ip6.snet eq ::1/128"
    expect_matcher_ok "ip6.snet eq ::/0"
    expect_matcher_ok "ip6.snet eq 2001:db8::8a2e:370:7334/96"
    expect_matcher_ok "ip6.snet eq ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
    expect_matcher_ok "ip6.snet eq 0:0:0:0:0:0:0:0/0"
    expect_matcher_ok "ip6.snet eq ::0/0"
    expect_matcher_ok "ip6.snet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"

    expect_matcher_nok "ip6.snet eq notanip"
    expect_matcher_nok "ip6.snet eq 1.1.1.1"
    expect_matcher_nok "ip6.snet eq 2001::db8::1"
    expect_matcher_nok "ip6.snet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.snet eq 2001:db8::/129"
    expect_matcher_nok "ip6.snet eq 2001:db8::/256"
    expect_matcher_nok "ip6.snet eq 2001:db8::/-1"
    expect_matcher_nok "ip6.snet eq 2001:db8::/999"
    expect_matcher_nok "ip6.snet eq ::ffff:192.168.0.0/96"
    expect_matcher_nok "ip6.snet eq 2001:0db81:85a3::8a2e:370:7334/48"
    expect_matcher_nok "ip6.snet eq 2001:xyz8::1/32"
    expect_matcher_nok "ip6.snet eq gggg::1/128"
    expect_matcher_nok "ip6.snet eq 2001:db8:://32"
    expect_matcher_nok "ip6.snet eq 2001:db8::/32/"
    expect_matcher_nok "ip6.snet eq 2001:db8::/32/48"
    expect_matcher_nok "ip6.snet eq 2001:db8::/3g"
    expect_matcher_nok "ip6.snet eq 2001:db8::/xx"
    expect_matcher_nok "ip6.snet eq /64"
    expect_matcher_nok "ip6.snet eq 2001:db8::1/"
    expect_matcher_nok "ip6.snet eq /128/"
    expect_matcher_nok "ip6.snet eq /2001:db8::/32"

    log "[SUITE] matcher: ip6.snet not"
    expect_matcher_ok "ip6.snet not 2001:db8::/32"
    expect_matcher_ok "ip6.snet not 2001:db8:85a3::/48"
    expect_matcher_ok "ip6.snet not fe80::/10"
    expect_matcher_ok "ip6.snet not 2001:db8:85a3:8d3::/64"
    expect_matcher_ok "ip6.snet not 2001:0db8:85a3:0000::/64"
    expect_matcher_ok "ip6.snet not 2001:db8::1/128"
    expect_matcher_ok "ip6.snet not ::1/128"
    expect_matcher_ok "ip6.snet not ::/0"
    expect_matcher_ok "ip6.snet not 2001:db8::8a2e:370:7334/96"
    expect_matcher_ok "ip6.snet not ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
    expect_matcher_ok "ip6.snet not 0:0:0:0:0:0:0:0/0"
    expect_matcher_ok "ip6.snet not ::0/0"
    expect_matcher_ok "ip6.snet not 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"

    expect_matcher_nok "ip6.snet not notanip"
    expect_matcher_nok "ip6.snet not 1.1.1.1"
    expect_matcher_nok "ip6.snet not 2001::db8::1"
    expect_matcher_nok "ip6.snet not 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.snet not 2001:db8::/129"
    expect_matcher_nok "ip6.snet not 2001:db8::/256"
    expect_matcher_nok "ip6.snet not 2001:db8::/-1"
    expect_matcher_nok "ip6.snet not 2001:db8::/999"
    expect_matcher_nok "ip6.snet not ::ffff:192.168.0.0/96"
    expect_matcher_nok "ip6.snet not 2001:0db81:85a3::8a2e:370:7334/48"
    expect_matcher_nok "ip6.snet not 2001:xyz8::1/32"
    expect_matcher_nok "ip6.snet not gggg::1/128"
    expect_matcher_nok "ip6.snet not 2001:db8:://32"
    expect_matcher_nok "ip6.snet not 2001:db8::/32/"
    expect_matcher_nok "ip6.snet not 2001:db8::/32/48"
    expect_matcher_nok "ip6.snet not 2001:db8::/3g"
    expect_matcher_nok "ip6.snet not 2001:db8::/xx"
    expect_matcher_nok "ip6.snet not /64"
    expect_matcher_nok "ip6.snet not 2001:db8::1/"
    expect_matcher_nok "ip6.snet not /128/"
    expect_matcher_nok "ip6.snet not /2001:db8::/32"

    log "[SUITE] matcher: ip6.dnet eq"
    expect_matcher_ok "ip6.dnet eq 2001:db8::/32"
    expect_matcher_ok "ip6.dnet eq 2001:db8:85a3::/48"
    expect_matcher_ok "ip6.dnet eq fe80::/10"
    expect_matcher_ok "ip6.dnet eq 2001:db8:85a3:8d3::/64"
    expect_matcher_ok "ip6.dnet eq 2001:0db8:85a3:0000::/64"
    expect_matcher_ok "ip6.dnet eq 2001:db8::1/128"
    expect_matcher_ok "ip6.dnet eq ::1/128"
    expect_matcher_ok "ip6.dnet eq ::/0"
    expect_matcher_ok "ip6.dnet eq 2001:db8::8a2e:370:7334/96"
    expect_matcher_ok "ip6.dnet eq ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
    expect_matcher_ok "ip6.dnet eq 0:0:0:0:0:0:0:0/0"
    expect_matcher_ok "ip6.dnet eq ::0/0"
    expect_matcher_ok "ip6.dnet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"

    expect_matcher_nok "ip6.dnet eq notanip"
    expect_matcher_nok "ip6.dnet eq 1.1.1.1"
    expect_matcher_nok "ip6.dnet eq 2001::db8::1"
    expect_matcher_nok "ip6.dnet eq 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/129"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/256"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/-1"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/999"
    expect_matcher_nok "ip6.dnet eq ::ffff:192.168.0.0/96"
    expect_matcher_nok "ip6.dnet eq 2001:0db81:85a3::8a2e:370:7334/48"
    expect_matcher_nok "ip6.dnet eq 2001:xyz8::1/32"
    expect_matcher_nok "ip6.dnet eq gggg::1/128"
    expect_matcher_nok "ip6.dnet eq 2001:db8:://32"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/32/"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/32/48"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/3g"
    expect_matcher_nok "ip6.dnet eq 2001:db8::/xx"
    expect_matcher_nok "ip6.dnet eq /64"
    expect_matcher_nok "ip6.dnet eq 2001:db8::1/"
    expect_matcher_nok "ip6.dnet eq /128/"
    expect_matcher_nok "ip6.dnet eq /2001:db8::/32"

    log "[SUITE] matcher: ip6.dnet not"
    expect_matcher_ok "ip6.dnet not 2001:db8::/32"
    expect_matcher_ok "ip6.dnet not 2001:db8:85a3::/48"
    expect_matcher_ok "ip6.dnet not fe80::/10"
    expect_matcher_ok "ip6.dnet not 2001:db8:85a3:8d3::/64"
    expect_matcher_ok "ip6.dnet not 2001:0db8:85a3:0000::/64"
    expect_matcher_ok "ip6.dnet not 2001:db8::1/128"
    expect_matcher_ok "ip6.dnet not ::1/128"
    expect_matcher_ok "ip6.dnet not ::/0"
    expect_matcher_ok "ip6.dnet not 2001:db8::8a2e:370:7334/96"
    expect_matcher_ok "ip6.dnet not ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
    expect_matcher_ok "ip6.dnet not 0:0:0:0:0:0:0:0/0"
    expect_matcher_ok "ip6.dnet not ::0/0"
    expect_matcher_ok "ip6.dnet not 2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"

    expect_matcher_nok "ip6.dnet not notanip"
    expect_matcher_nok "ip6.dnet not 1.1.1.1"
    expect_matcher_nok "ip6.dnet not 2001::db8::1"
    expect_matcher_nok "ip6.dnet not 2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    expect_matcher_nok "ip6.dnet not 2001:db8::/129"
    expect_matcher_nok "ip6.dnet not 2001:db8::/256"
    expect_matcher_nok "ip6.dnet not 2001:db8::/-1"
    expect_matcher_nok "ip6.dnet not 2001:db8::/999"
    expect_matcher_nok "ip6.dnet not ::ffff:192.168.0.0/96"
    expect_matcher_nok "ip6.dnet not 2001:0db81:85a3::8a2e:370:7334/48"
    expect_matcher_nok "ip6.dnet not 2001:xyz8::1/32"
    expect_matcher_nok "ip6.dnet not gggg::1/128"
    expect_matcher_nok "ip6.dnet not 2001:db8:://32"
    expect_matcher_nok "ip6.dnet not 2001:db8::/32/"
    expect_matcher_nok "ip6.dnet not 2001:db8::/32/48"
    expect_matcher_nok "ip6.dnet not 2001:db8::/3g"
    expect_matcher_nok "ip6.dnet not 2001:db8::/xx"
    expect_matcher_nok "ip6.dnet not /64"
    expect_matcher_nok "ip6.dnet not 2001:db8::1/"
    expect_matcher_nok "ip6.dnet not /128/"
    expect_matcher_nok "ip6.dnet not /2001:db8::/32"

    log "[SUITE] matcher: ip6.nexthdr eq"
    expect_matcher_ok "ip6.nexthdr eq icmp"
    expect_matcher_ok "ip6.nexthdr eq hop"
    expect_matcher_ok "ip6.nexthdr eq HOP"
    expect_matcher_ok "ip6.nexthdr eq 17"
    expect_matcher_ok "ip6.nexthdr eq 255"

    expect_matcher_nok "ip6.nexthdr eq ipv4"
    expect_matcher_nok "ip6.nexthdr eq imcp"
    expect_matcher_nok "ip6.nexthdr eq 0x342"
    expect_matcher_nok "ip6.nexthdr eq -18"
    expect_matcher_nok "ip6.nexthdr eq 256"

    log "[SUITE] matcher: ip6.nexthdr not"
    expect_matcher_ok "ip6.nexthdr not icmp"
    expect_matcher_ok "ip6.nexthdr not hop"
    expect_matcher_ok "ip6.nexthdr not HOP"
    expect_matcher_ok "ip6.nexthdr not 17"
    expect_matcher_ok "ip6.nexthdr not 255"

    expect_matcher_nok "ip6.nexthdr not ipv4"
    expect_matcher_nok "ip6.nexthdr not imcp"
    expect_matcher_nok "ip6.nexthdr not 0x342"
    expect_matcher_nok "ip6.nexthdr not -18"
    expect_matcher_nok "ip6.nexthdr not 256"
}
with_daemon suite_matcher_ip6

suite_matcher_tcp() {
    log "[SUITE] matcher: tcp.sport eq"
    expect_matcher_ok "tcp.sport eq 0"
    expect_matcher_ok "tcp.sport eq 40"
    expect_matcher_ok "tcp.sport eq 65535"

    expect_matcher_nok "tcp.sport eq -40"
    expect_matcher_nok "tcp.sport eq 0x40"
    expect_matcher_nok "tcp.sport eq -0x00"
    expect_matcher_nok "tcp.sport eq 75000"
    expect_matcher_nok "tcp.sport eq 0xffffff"
    expect_matcher_nok "tcp.sport eq not_a_port"

    log "[SUITE] matcher: tcp.sport not"
    expect_matcher_ok "tcp.sport not 0"
    expect_matcher_ok "tcp.sport not 40"
    expect_matcher_ok "tcp.sport not 65535"

    expect_matcher_nok "tcp.sport not -40"
    expect_matcher_nok "tcp.sport not 0x40"
    expect_matcher_nok "tcp.sport not -0x00"
    expect_matcher_nok "tcp.sport not 75000"
    expect_matcher_nok "tcp.sport not 0xffffff"
    expect_matcher_nok "tcp.sport not not_a_port"

    log "[SUITE] matcher: tcp.sport range"
    expect_matcher_ok "tcp.sport range 0-0"
    expect_matcher_ok "tcp.sport range 0-65535"
    expect_matcher_ok "tcp.sport range 17-30"

    expect_matcher_nok "tcp.sport range 0"
    expect_matcher_nok "tcp.sport range 20-10"
    expect_matcher_nok "tcp.sport range 10-20-30"
    expect_matcher_nok "tcp.sport range 10000000-1000000"
    expect_matcher_nok "tcp.sport range 0x20"
    expect_matcher_nok "tcp.sport range 0x20-0x30"
    expect_matcher_nok "tcp.sport range 0x30-0x20"
    expect_matcher_nok "tcp.sport range -1-4"
    expect_matcher_nok "tcp.sport range -1--4"
    expect_matcher_nok "tcp.sport range not-port"
    expect_matcher_nok "tcp.sport range notport"

    log "[SUITE] matcher: tcp.dport eq"
    expect_matcher_ok "tcp.dport eq 0"
    expect_matcher_ok "tcp.dport eq 40"
    expect_matcher_ok "tcp.dport eq 65535"

    expect_matcher_nok "tcp.dport eq -40"
    expect_matcher_nok "tcp.dport eq 0x40"
    expect_matcher_nok "tcp.dport eq -0x00"
    expect_matcher_nok "tcp.dport eq 75000"
    expect_matcher_nok "tcp.dport eq 0xffffff"
    expect_matcher_nok "tcp.dport eq not_a_port"

    log "[SUITE] matcher: tcp.dport not"
    expect_matcher_ok "tcp.dport not 0"
    expect_matcher_ok "tcp.dport not 40"
    expect_matcher_ok "tcp.dport not 65535"

    expect_matcher_nok "tcp.dport not -40"
    expect_matcher_nok "tcp.dport not 0x40"
    expect_matcher_nok "tcp.dport not -0x00"
    expect_matcher_nok "tcp.dport not 75000"
    expect_matcher_nok "tcp.dport not 0xffffff"
    expect_matcher_nok "tcp.dport not not_a_port"

    log "[SUITE] matcher: tcp.dport range"
    expect_matcher_ok "tcp.dport range 0-0"
    expect_matcher_ok "tcp.dport range 0-65535"
    expect_matcher_ok "tcp.dport range 17-30"

    expect_matcher_nok "tcp.dport range 0"
    expect_matcher_nok "tcp.dport range 20-10"
    expect_matcher_nok "tcp.dport range 10-20-30"
    expect_matcher_nok "tcp.dport range 10000000-1000000"
    expect_matcher_nok "tcp.dport range 0x20"
    expect_matcher_nok "tcp.dport range 0x20-0x30"
    expect_matcher_nok "tcp.dport range 0x30-0x20"
    expect_matcher_nok "tcp.dport range -1-4"
    expect_matcher_nok "tcp.dport range -1--4"
    expect_matcher_nok "tcp.dport range not-port"
    expect_matcher_nok "tcp.dport range notport"

    log "[SUITE] matcher: tcp.flags eq"
    expect_matcher_ok "tcp.flags eq fin"
    expect_matcher_ok "tcp.flags eq fin,syn,rst,psh,ack"
    expect_matcher_ok "tcp.flags eq fin,syn,rst,psh,ack,urg"
    expect_matcher_ok "tcp.flags eq fin,syn,rst,psh,ack,urg,ece"
    expect_matcher_ok "tcp.flags eq fin,syn,rst,psh,ack,urg,ece,cwr"
    expect_matcher_ok "tcp.flags eq syn,fin"
    expect_matcher_ok "tcp.flags eq cwr,fin,ack"

    expect_matcher_nok "tcp.flags eq invalid"
    expect_matcher_nok "tcp.flags eq fin,syn,rst,psh,ack,urg,ece,cwr,invalid"

    log "[SUITE] matcher: tcp.flags not"
    expect_matcher_ok "tcp.flags not fin"
    expect_matcher_ok "tcp.flags not syn"
    expect_matcher_ok "tcp.flags not rst"
    expect_matcher_ok "tcp.flags not psh"
    expect_matcher_ok "tcp.flags not fin,syn,rst,psh,ack"
    expect_matcher_ok "tcp.flags not fin,syn,rst,psh,ack,urg"
    expect_matcher_ok "tcp.flags not fin,syn,rst,psh,ack,urg,ece"
    expect_matcher_ok "tcp.flags not fin,syn,rst,psh,ack,urg,ece,cwr"

    expect_matcher_nok "tcp.flags not invalid"
    expect_matcher_nok "tcp.flags not fin,syn,rst,psh,ack,urg,ece,cwr,invalid"

    log "[SUITE] matcher: tcp.flags any"
    expect_matcher_ok "tcp.flags any fin"
    expect_matcher_ok "tcp.flags any fin,syn,rst,psh,ack"
    expect_matcher_ok "tcp.flags any fin,syn,rst,psh,ack,urg"
    expect_matcher_ok "tcp.flags any fin,syn,rst,psh,ack,urg,ece"
    expect_matcher_ok "tcp.flags any fin,syn,rst,psh,ack,urg,ece,cwr"
    expect_matcher_ok "tcp.flags any syn,fin"
    expect_matcher_ok "tcp.flags any cwr,fin,ack"

    expect_matcher_nok "tcp.flags any invalid"
    expect_matcher_nok "tcp.flags any fin,invalid"
    expect_matcher_nok "tcp.flags any fin,,syn"

    log "[SUITE] matcher: tcp.flags all"
    expect_matcher_ok "tcp.flags all fin"
    expect_matcher_ok "tcp.flags all syn"
    expect_matcher_ok "tcp.flags all fin,syn"
    expect_matcher_ok "tcp.flags all fin,syn,rst"
    expect_matcher_ok "tcp.flags all fin,syn,rst,psh"
    expect_matcher_ok "tcp.flags any fin,fin,syn"

    expect_matcher_nok "tcp.flags all fin,syn,rst,psh,ack,urg,ece,cwr,invalid"
}
with_daemon suite_matcher_tcp

suite_matcher_udp() {
    log "[SUITE] matcher: udp.sport eq"
    expect_matcher_ok "udp.sport eq 0"
    expect_matcher_ok "udp.sport eq 40"
    expect_matcher_ok "udp.sport eq 65535"

    expect_matcher_nok "udp.sport eq -40"
    expect_matcher_nok "udp.sport eq 0x40"
    expect_matcher_nok "udp.sport eq -0x00"
    expect_matcher_nok "udp.sport eq 75000"
    expect_matcher_nok "udp.sport eq 0xffffff"
    expect_matcher_nok "udp.sport eq not_a_port"

    log "[SUITE] matcher: udp.sport not"
    expect_matcher_ok "udp.sport not 0"
    expect_matcher_ok "udp.sport not 40"
    expect_matcher_ok "udp.sport not 65535"

    expect_matcher_nok "udp.sport not -40"
    expect_matcher_nok "udp.sport not 0x40"
    expect_matcher_nok "udp.sport not -0x00"
    expect_matcher_nok "udp.sport not 75000"
    expect_matcher_nok "udp.sport not 0xffffff"
    expect_matcher_nok "udp.sport not not_a_port"

    log "[SUITE] matcher: udp.sport range"
    expect_matcher_ok "udp.sport range 0-0"
    expect_matcher_ok "udp.sport range 0-65535"
    expect_matcher_ok "udp.sport range 17-30"

    expect_matcher_nok "udp.sport range 0"
    expect_matcher_nok "udp.sport range 20-10"
    expect_matcher_nok "udp.sport range 10-20-30"
    expect_matcher_nok "udp.sport range 10000000-1000000"
    expect_matcher_nok "udp.sport range 0x20"
    expect_matcher_nok "udp.sport range 0x20-0x30"
    expect_matcher_nok "udp.sport range 0x30-0x20"
    expect_matcher_nok "udp.sport range -1-4"
    expect_matcher_nok "udp.sport range -1--4"
    expect_matcher_nok "udp.sport range not-port"
    expect_matcher_nok "udp.sport range notport"

    log "[SUITE] matcher: udp.dport eq"
    expect_matcher_ok "udp.dport eq 0"
    expect_matcher_ok "udp.dport eq 40"
    expect_matcher_ok "udp.dport eq 65535"

    expect_matcher_nok "udp.dport eq -40"
    expect_matcher_nok "udp.dport eq 0x40"
    expect_matcher_nok "udp.dport eq -0x00"
    expect_matcher_nok "udp.dport eq 75000"
    expect_matcher_nok "udp.dport eq 0xffffff"
    expect_matcher_nok "udp.dport eq not_a_port"

    log "[SUITE] matcher: udp.dport not"
    expect_matcher_ok "udp.dport not 0"
    expect_matcher_ok "udp.dport not 40"
    expect_matcher_ok "udp.dport not 65535"

    expect_matcher_nok "udp.dport not -40"
    expect_matcher_nok "udp.dport not 0x40"
    expect_matcher_nok "udp.dport not -0x00"
    expect_matcher_nok "udp.dport not 75000"
    expect_matcher_nok "udp.dport not 0xffffff"
    expect_matcher_nok "udp.dport not not_a_port"

    log "[SUITE] matcher: udp.dport range"
    expect_matcher_ok "udp.dport range 0-0"
    expect_matcher_ok "udp.dport range 0-65535"
    expect_matcher_ok "udp.dport range 17-30"

    expect_matcher_nok "udp.dport range 0"
    expect_matcher_nok "udp.dport range 20-10"
    expect_matcher_nok "udp.dport range 10-20-30"
    expect_matcher_nok "udp.dport range 10000000-1000000"
    expect_matcher_nok "udp.dport range 0x20"
    expect_matcher_nok "udp.dport range 0x20-0x30"
    expect_matcher_nok "udp.dport range 0x30-0x20"
    expect_matcher_nok "udp.dport range -1-4"
    expect_matcher_nok "udp.dport range -1--4"
    expect_matcher_nok "udp.dport range not-port"
    expect_matcher_nok "udp.dport range notport"
}
with_daemon suite_matcher_udp

suite_matcher_icmp() {
    log "[SUITE] matcher: icmp.type eq"
    expect_matcher_ok "icmp.type eq echo-reply"
    expect_matcher_ok "icmp.type eq router-advertisement"
    expect_matcher_ok "icmp.type eq 0x23"
    expect_matcher_ok "icmp.type eq 14"

    expect_matcher_nok "icmp.type eq echo-repl"
    expect_matcher_nok "icmp.type eq r"
    expect_matcher_nok "icmp.type eq 0xf23"
    expect_matcher_nok "icmp.type eq -14"
    expect_matcher_nok "icmp.type eq 45574614"

    log "[SUITE] matcher: icmp.type not"
    expect_matcher_ok "icmp.type not echo-reply"
    expect_matcher_ok "icmp.type not router-advertisement"
    expect_matcher_ok "icmp.type not 0x23"
    expect_matcher_ok "icmp.type not 14"

    expect_matcher_nok "icmp.type not echo-repl"
    expect_matcher_nok "icmp.type not r"
    expect_matcher_nok "icmp.type not 0xf23"
    expect_matcher_nok "icmp.type not -14"
    expect_matcher_nok "icmp.type not 45574614"

    log "[SUITE] matcher: icmp.code eq"
    expect_matcher_ok "icmp.code eq 0"
    expect_matcher_ok "icmp.code eq 10"
    expect_matcher_ok "icmp.code eq 255"
    expect_matcher_ok "icmp.code eq 0x00"
    expect_matcher_ok "icmp.code eq 0x17"
    expect_matcher_ok "icmp.code eq 0xff"

    expect_matcher_nok "icmp.code eq auf"
    expect_matcher_nok "icmp.code eq -1"
    expect_matcher_nok "icmp.code eq 257"
    expect_matcher_nok "icmp.code eq -0x01"
    expect_matcher_nok "icmp.code eq -0xffff"

    log "[SUITE] matcher: icmp.code not"
    expect_matcher_ok "icmp.code not 0"
    expect_matcher_ok "icmp.code not 10"
    expect_matcher_ok "icmp.code not 255"
    expect_matcher_ok "icmp.code not 0x00"
    expect_matcher_ok "icmp.code not 0x17"
    expect_matcher_ok "icmp.code not 0xff"

    expect_matcher_nok "icmp.code not auf"
    expect_matcher_nok "icmp.code not -1"
    expect_matcher_nok "icmp.code not 257"
    expect_matcher_nok "icmp.code not -0x01"
    expect_matcher_nok "icmp.code not -0xffff"
}
with_daemon suite_matcher_icmp

suite_matcher_icmpv6() {
    log "[SUITE] matcher: icmpv6.type eq"
    expect_matcher_ok "icmpv6.type eq mld-listener-report"
    expect_matcher_ok "icmpv6.type eq echo-request"
    expect_matcher_ok "icmpv6.type eq 0x23"
    expect_matcher_ok "icmpv6.type eq 14"

    expect_matcher_nok "icmpv6.type eq echo-repl"
    expect_matcher_nok "icmpv6.type eq r"
    expect_matcher_nok "icmpv6.type eq 0xf23"
    expect_matcher_nok "icmpv6.type eq -14"
    expect_matcher_nok "icmpv6.type eq 45574614"

    log "[SUITE] matcher: icmpv6.type not"
    expect_matcher_ok "icmpv6.type not mld-listener-report"
    expect_matcher_ok "icmpv6.type not echo-request"
    expect_matcher_ok "icmpv6.type not 0x23"
    expect_matcher_ok "icmpv6.type not 14"

    expect_matcher_nok "icmpv6.type not echo-repl"
    expect_matcher_nok "icmpv6.type not r"
    expect_matcher_nok "icmpv6.type not 0xf23"
    expect_matcher_nok "icmpv6.type not -14"
    expect_matcher_nok "icmpv6.type not 45574614"

    log "[SUITE] matcher: icmpv6.code eq"
    expect_matcher_ok "icmpv6.code eq 0"
    expect_matcher_ok "icmpv6.code eq 10"
    expect_matcher_ok "icmpv6.code eq 255"
    expect_matcher_ok "icmpv6.code eq 0x00"
    expect_matcher_ok "icmpv6.code eq 0x17"
    expect_matcher_ok "icmpv6.code eq 0xff"

    expect_matcher_nok "icmpv6.code eq auf"
    expect_matcher_nok "icmpv6.code eq -1"
    expect_matcher_nok "icmpv6.code eq 257"
    expect_matcher_nok "icmpv6.code eq -0x01"
    expect_matcher_nok "icmpv6.code eq -0xffff"

    log "[SUITE] matcher: icmpv6.code not"
    expect_matcher_ok "icmpv6.code not 0"
    expect_matcher_ok "icmpv6.code not 10"
    expect_matcher_ok "icmpv6.code not 255"
    expect_matcher_ok "icmpv6.code not 0x00"
    expect_matcher_ok "icmpv6.code not 0x17"
    expect_matcher_ok "icmpv6.code not 0xff"

    expect_matcher_nok "icmpv6.code not auf"
    expect_matcher_nok "icmpv6.code not -1"
    expect_matcher_nok "icmpv6.code not 257"
    expect_matcher_nok "icmpv6.code not -0x01"
    expect_matcher_nok "icmpv6.code not -0xffff"
}
with_daemon suite_matcher_icmpv6

suite_generate_for_each_hook() {
    log "[SUITE] cli: generate a chain for each hook"
    for file in "$RULESETS_DIR"/*.bf; do
        expect_success "generate chain for $(basename $file .bf)" \
            ${FROM_NS} ${BFCLI} chain set --from-file ${file}
    done
}
with_daemon suite_generate_for_each_hook

################################################################################
#
# Cleanup
#
################################################################################

exit 0
