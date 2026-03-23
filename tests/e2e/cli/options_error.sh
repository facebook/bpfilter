#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

(! ${BFCLI} ruleset set --from-str "" --from-file "")
(! ${BFCLI} ruleset set)

(! ${BFCLI} chain set --from-str "" --from-file "")
(! ${BFCLI} chain set)

(! ${BFCLI} chain get)

(! ${BFCLI} chain logs)

(! ${BFCLI} chain load --from-str "" --from-file "")
(! ${BFCLI} chain load)

(! ${BFCLI} chain attach)

(! ${BFCLI} chain attach --from-str "" --from-file "")
(! ${BFCLI} chain attach)

(! ${BFCLI} chain flush)
