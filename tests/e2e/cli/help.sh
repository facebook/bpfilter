#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

set -euo pipefail
export LC_ALL=C

version=$(bfcli --version)

check_command() {
    local object=$1 action=$2
    local flag output

    for flag in --help -h --usage; do
        output=$(bfcli "$object" "$action" "$flag")
        grep -Fq "Usage: bfcli $object $action " <<< "$output"

        if [[ "$flag" != --usage ]]; then
            for option in --help --usage --version; do
                grep -Fq -- "$option" <<< "$output"
            done
        fi
    done

    for flag in --version -V; do
        output=$(bfcli "$object" "$action" "$flag")
        [[ "$output" == "$version" ]]
    done
}

for action in set get flush; do
    check_command ruleset "$action"
done

for action in set get logs load attach update update-set flush; do
    check_command chain "$action"
done
