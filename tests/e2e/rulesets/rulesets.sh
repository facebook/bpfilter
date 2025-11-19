#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

for file in "$(dirname -- "$0";)"/*.bf; do
    ${FROM_NS} bfcli chain set --from-file ${file}
done