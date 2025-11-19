#!/usr/bin/env bash

set -eux
set -o pipefail

. "$(dirname "$0")"/../e2e_test_util.sh

(! bfcli ruleset set --from-str "" --from-file "")
(! bfcli ruleset set)

(! bfcli chain set --from-str "" --from-file "")
(! bfcli chain set)

(! bfcli chain get)

(! bfcli chain logs)

(! bfcli chain load --from-str "" --from-file "")
(! bfcli chain load)

(! bfcli chain attach)

(! bfcli chain attach --from-str "" --from-file "")
(! bfcli chain attach)

(! bfcli chain flush)