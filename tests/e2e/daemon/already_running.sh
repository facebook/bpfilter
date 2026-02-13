#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

(! ${FROM_NS} ${WITH_TIMEOUT} ${BPFILTER})