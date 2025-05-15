#!/usr/bin/env bash

set -e

# Define variables
WORKDIR=$(mktemp -d)
NS_OUTPUT_FILE=${WORKDIR}/ns.log

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

expect_success() {
    local description="$1"
    shift

    # Build the command string for eval
    local cmd="$*"

    # Capture both stdout and stderr
    local output
    local result=0
    output=$(eval "$cmd" 2>&1) || result=$?

    if [ $result -eq 0 ]; then
        # Success case - we expected 0 exit code and got it
        echo -e "${GREEN}[+] -> Success: ${GREEN_BOLD}${description}${RESET}" >&2
        return 0
    else
        # Failure case - we expected 0 exit code but got non-zero
        echo -e "${RED}[-] -> Failure: ${RED_BOLD}${description}${RESET}" >&2
        echo -e "${YELLOW}Command:${RESET} $cmd" >&2
        echo -e "${YELLOW}Output:${RESET}" >&2
        echo "$output" >&2
        echo -e "${YELLOW}Expected exit code 0 but got ${result}${RESET}" >&2
        echo >&2
        return 1
    fi
}

expect_failure() {
    local description="$1"
    shift

    # Build the command string for eval
    local cmd="$*"

    # Capture both stdout and stderr
    local output
    local result=0
    output=$(eval "$cmd" 2>&1) || result=$?

    if [ $result -eq 0 ]; then
        # Failure case - we expected a non-zero exit code but got 0
        echo -e "${RED}[-] -> Failure: ${RED_BOLD}${description}${RESET}" >&2
        echo -e "${YELLOW}Command:${RESET} $cmd" >&2
        echo -e "${YELLOW}Output:${RESET}" >&2
        echo "$output" >&2
        echo -e "${YELLOW}Expected non-zero exit code but got 0${RESET}" >&2
        echo >&2
        return 1
    else
        # Success case - we expected a non-zero exit code and got one
        echo -e "${GREEN}[+] -> Success: ${GREEN_BOLD}${description}${RESET}" >&2
        return 0
    fi
}

# Function to cleanup on exit or error
cleanup() {
    cat ${NS_OUTPUT_FILE}

    umount ${WORKDIR}/ns/user
    umount ${WORKDIR}/ns/mnt
    umount ${WORKDIR}/ns
    rm -rf ${WORKDIR}

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

BPFILTER=

# Function to display usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --bpfilter PATH   Path to bpfilter executable"
    echo "  -h, --help        Display this help message and exit"
    exit 1
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bpfilter)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --bpfilter requires a path argument."
                usage
            fi
            BPFILTER=$(realpath $2)
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

mkdir ${WORKDIR}/ns
mount --bind ${WORKDIR}/ns ${WORKDIR}/ns
mount --make-private ${WORKDIR}/ns

touch ${WORKDIR}/ns/{user,mnt}

unshare --user=${WORKDIR}/ns/user --mount=${WORKDIR}/ns/mnt --keep-caps --map-groups=all --map-users=all -r /bin/bash -c "
    set -e
    mount -t tmpfs tmpfs /run
" > "$NS_OUTPUT_FILE" 2>&1 &

sleep .25

FROM_NS="nsenter --mount=${WORKDIR}/ns/mnt --user=${WORKDIR}/ns/user"
WITH_TIMEOUT="timeout --signal INT --preserve-status .5"


################################################################################
#
# Run tests
#
################################################################################

log "[SUITE] daemon: handle existing daemon and leftover socket"
expect_success "start bpfilter in a clean environment" \
    ${FROM_NS} ${WITH_TIMEOUT} ${BPFILTER}
expect_success "create a fake socket file" \
    ${FROM_NS} touch /run/bpfilter/daemon.sock
expect_success "socket file exists, but no daemon running" \
    ${FROM_NS} ${WITH_TIMEOUT} ${BPFILTER}


################################################################################
#
# Cleanup
#
################################################################################

exit 0
