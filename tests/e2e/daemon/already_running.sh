#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

# shellcheck disable=SC2086 # Word splitting is intentional for command variables
(! ${FROM_NS} ${WITH_TIMEOUT} ${BPFILTER})