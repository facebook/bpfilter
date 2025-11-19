#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

${FROM_NS} mkdir /run/bpfilter
${FROM_NS} touch /run/bpfilter/daemon.sock
${FROM_NS} ${WITH_TIMEOUT} ${BPFILTER}