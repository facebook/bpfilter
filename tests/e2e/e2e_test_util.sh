#!/bin/bash

set -eux

WORKDIR=$(mktemp -d)
BF_OUTPUT_FILE=${WORKDIR}/bf.log
BPFILTER_PID=
SETUSERNS_SOCKET_PATH=${WORKDIR}/setuserns.sock

IN_SANBOX=0
WITH_DAEMON=0
HAS_TOKEN_SUPPORT=0
TEST_PATH=
FROM_NS=

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
BFCLI=bfcli
_BPFILTER=bpfilter
BPFILTER= # bpfilter command to use in tests (includes the required options)
SETUSERNS=setuserns
RULESETS_DIR=.

################################################################################
#
# Setup
#
################################################################################

make_sandbox() {
    echo "Create the sandbox"

    IN_SANBOX=1

    # Disable selinux if available, not all distros enforce setlinux
    if command -v setenforce &> /dev/null; then
        setenforce 0 || true
    fi

    # Check if BPF token is supported
    bash -c "sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -q \"__s32 prog_token_fd;\"" && HAS_TOKEN_SUPPORT=1 || HAS_TOKEN_SUPPORT=0

    # Create the namespaces mount points
    mkdir ${WORKDIR}/{ns,bpf}
    mount --bind ${WORKDIR}/ns ${WORKDIR}/ns
    mount --make-private ${WORKDIR}/ns

    touch ${WORKDIR}/ns/{user,mnt}

    # Create the netns to be used by unshare
    ip netns add ${NETNS_NAME}

    # Create the user and mount namespaces, mount a new /run to have the bpfilter socket
    if [ $HAS_TOKEN_SUPPORT -eq 1 ]; then
        ${SETUSERNS} out --socket ${SETUSERNS_SOCKET_PATH} &
        SETUSERNS_PID=$!

        # util-linux 2.38+ supports --map-users/--map-groups
        UNSHARE_VERSION=$(unshare --version | grep -oP '\d+\.\d+' | head -1)
        if [ "$(printf '%s\n' "2.38" "$UNSHARE_VERSION" | sort -V | head -1)" = "2.38" ]; then
            UNSHARE_MAP_OPTS="--map-users=all --map-groups=all"
        else
            UNSHARE_MAP_OPTS=""
        fi

        unshare \
            --user=${WORKDIR}/ns/user \
            --mount=${WORKDIR}/ns/mnt \
            --net=/var/run/netns/${NETNS_NAME} \
            --keep-caps \
            ${UNSHARE_MAP_OPTS} \
            -r /bin/bash -c "
                set -e
                mount -t tmpfs tmpfs /run
                ${SETUSERNS} in --socket ${SETUSERNS_SOCKET_PATH} --bpffs-mount-path ${WORKDIR}/bpf
        " &

        BPFILTER="${_BPFILTER} --verbose debug --with-bpf-token --bpffs-path ${WORKDIR}/bpf"
        wait $SETUSERNS_PID
    else
        unshare --net=/var/run/netns/${NETNS_NAME} &
        BPFILTER="${_BPFILTER} --verbose debug"
    fi

    if [ "${HAS_TOKEN_SUPPORT:-1}" -eq 1 ]; then
        FROM_NS="nsenter --mount=${WORKDIR}/ns/mnt --user=${WORKDIR}/ns/user --net=/var/run/netns/${NETNS_NAME}"
    else
        FROM_NS="nsenter --net=/var/run/netns/${NETNS_NAME}"
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

    echo "End-to-end test configuration:"
    echo "  Workdir: ${WORKDIR}"
    echo "  Network interfaces:"
    echo "    ${HOST_IFINDEX}: ${VETH_HOST} @ ${HOST_IP_ADDR}"
    echo "    ${NS_IFINDEX}: ${VETH_NS} @ ${NS_IP_ADDR}"
    echo "  Tested binaries"
    echo "    bfcli: ${BFCLI}"
    echo "    bpfilter: ${_BPFILTER}"
    echo "    setuserns: ${SETUSERNS}"
    echo "    rulesets-dir: ${RULESETS_DIR}"
}

destroy_sandbox() {
    echo "Cleanup the sandbox"

    # netns should be unmounted AND deleted
    umount /var/run/netns/${NETNS_NAME} || true
    ip netns delete ${NETNS_NAME} || true

    # If BPF token is not supported, user and mnt namespaces are not mounted
    if [ "${HAS_TOKEN_SUPPORT:-1}" -eq 1 ]; then
        umount ${WORKDIR}/bpf || true
        umount ${WORKDIR}/ns/user || true
        umount ${WORKDIR}/ns/mnt || true
    fi

    umount ${WORKDIR}/ns || true

    rm -rf ${WORKDIR} || true

    IN_SANDBOX=0
}

start_bpfilter() {
    echo "Start bpfilter"

    local timeout=10
    local start_time=$(date +%s)
    local end_time=$((start_time + timeout))

    ${FROM_NS} ${BPFILTER} > ${BF_OUTPUT_FILE} 2>&1 &
    BPFILTER_PID=$!

    # Wait for the daemon to listen to the requests
    while [ $(date +%s) -lt $end_time ]; do
        if grep -q "waiting for requests" "${BF_OUTPUT_FILE}"; then
            WITH_DAEMON=1
            return 0
        fi
        sleep 0.1
    done

    return 1
}

stop_bpfilter() {
    local skip_cleanup=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-cleanup)
                skip_cleanup=1
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    echo "Stop bpfilter"

    if [ -n "$BPFILTER_PID" ]; then
        if [ "$skip_cleanup" -eq 0 ] && [ "${HAS_TOKEN_SUPPORT:-1}" -ne 1 ]; then
            bfcli ruleset flush || true
        fi

        kill $BPFILTER_PID 2>/dev/null || true
        wait $BPFILTER_PID || true
    fi

    WITH_DAEMON=0
}

cleanup() {
    echo "cleanup() called with exit value $1"

    if [ "$WITH_DAEMON" -ne 0 ]; then
        stop_bpfilter

        echo "========== bpfilter output =========="
        cat "$BF_OUTPUT_FILE" || true
    fi

    if [ "$IN_SANBOX" -ne 0 ]; then
        destroy_sandbox
    fi

    exit $1
}

# Set trap to ensure cleanup happens
trap 'cleanup $?' EXIT
trap 'cleanup 1' INT TERM


################################################################################
#
# Testing
#
################################################################################

WITH_TIMEOUT="timeout --signal INT --preserve-status .5"
