#!/bin/bash

set -eux

TEST_PATH=
FROM_NS=

# Derive resources names from the test name. Allows for pre-test cleanup
# and parallel testing of different tests.
_TEST_NAME=$(basename "$0" .sh)
_TEST_HASH=$(printf '%s' "$_TEST_NAME" | cksum | awk '{print $1}')
_OCTET2=$(( (_TEST_HASH >> 8) & 0xFF ))
_OCTET3=$(( _TEST_HASH & 0xFF ))
_SHORT_ID=$(( _TEST_HASH & 0xFFFF ))

WORKDIR="/tmp/bpfilter.e2e.${_TEST_NAME}"
_UNIT_NAME="bpfilter-e2e-${_TEST_NAME}"
BF_OUTPUT_FILE=${WORKDIR}/bf.log
BPFILTER_PID=

NETNS_NAME="bftest_${_TEST_NAME}"
VETH_HOST="veth_h_${_SHORT_ID}"
VETH_NS="veth_n_${_SHORT_ID}"
HOST_IP="10.${_OCTET2}.${_OCTET3}.1/24"
NS_IP="10.${_OCTET2}.${_OCTET3}.2/24"
HOST_IP_ADDR="10.${_OCTET2}.${_OCTET3}.1"
NS_IP_ADDR="10.${_OCTET2}.${_OCTET3}.2"
HOST_IFINDEX=
NS_IFINDEX=

# Tested binaries
BFCLI=bfcli
_BPFILTER=$(command -v bpfilter)
BPFILTER= # bpfilter command to use in tests (includes the required options)
RULESETS_DIR=.

################################################################################
#
# Setup
#
################################################################################

make_sandbox() {
    echo "Create the sandbox"

    # Disable selinux if available, not all distros enforce setlinux
    if command -v setenforce &> /dev/null; then
        setenforce 0 || true
    fi

    # Create the namespaces mount points
    mkdir ${WORKDIR}/{ns,bpf}
    mount --bind ${WORKDIR}/ns ${WORKDIR}/ns
    mount --make-private ${WORKDIR}/ns

    touch ${WORKDIR}/ns/{user,mnt}

    # Create the netns to be used by unshare
    ip netns add ${NETNS_NAME}

        unshare \
            --mount=${WORKDIR}/ns/mnt \
            --net=/var/run/netns/${NETNS_NAME} \
            --keep-caps \
        /bin/bash -c "
                set -e
                mount -t tmpfs tmpfs /run
            mount -t bpf bpf ${WORKDIR}/bpf
    "

    BPFILTER="${_BPFILTER} --verbose debug --bpffs-path ${WORKDIR}/bpf"

    FROM_NS="nsenter --mount=${WORKDIR}/ns/mnt --net=/var/run/netns/${NETNS_NAME}"

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
    echo "    rulesets-dir: ${RULESETS_DIR}"
}

destroy_sandbox() {
    echo "Cleanup the sandbox"

    # netns should be unmounted AND deleted
    umount /var/run/netns/${NETNS_NAME} || true
    ip netns delete ${NETNS_NAME} || true

        umount ${WORKDIR}/bpf || true
        umount ${WORKDIR}/ns/mnt || true
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

    if [ "$skip_cleanup" -eq 0 ]; then
        bfcli ruleset flush || true
    fi

    kill $BPFILTER_PID 2>/dev/null || true
    wait $BPFILTER_PID || true

    echo "========== bpfilter output =========="
    cat "$BF_OUTPUT_FILE" || true
}

cleanup() {
    stop_bpfilter
    destroy_sandbox
}

# Set trap to ensure cleanup happens
trap 'ret=$?; cleanup; exit ${ret}' EXIT
trap 'cleanup 1; exit 1' INT TERM


################################################################################
#
# Testing
#
################################################################################

WITH_TIMEOUT="timeout --signal INT --preserve-status .5"

cleanup
mkdir -p ${WORKDIR}