#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

for file in "$(dirname -- "$0";)"/*.bf; do
    ${FROM_NS} ${BFCLI} chain set --from-file ${file}
done