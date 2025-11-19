# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_executable(setuserns EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/setuserns.c
)

target_link_libraries(setuserns
    PRIVATE
        bf_global_flags
        libbpfilter
)

function(bf_add_e2e_test GROUP SOURCE)
    cmake_parse_arguments(
        ARG
        "ROOT"
        ""
        ""
        ${ARGN}
    )

    set(source_wo_ext ${SOURCE})
    cmake_path(REMOVE_EXTENSION source_wo_ext)
    string(REPLACE "/" "." target_suffix "${source_wo_ext}")

    set(target_name "${GROUP}.${target_suffix}")

    add_dependencies(test_bin bpfilter bfcli setuserns)

    if (ARG_ROOT)
        set(AS_ROOT ${CMAKE_SOURCE_DIR}/tools/asroot)
    endif ()

    add_test(NAME ${target_name}
        COMMAND
            ${AS_ROOT} ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE}
    )

    set_tests_properties(${target_name} PROPERTIES
        LABELS "${GROUP}"
        ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/output/sbin:${CMAKE_CURRENT_SOURCE_DIR}:$ENV{PATH}"
    )
endfunction()

bf_add_e2e_test(e2e cli/chain_attach.sh ROOT)
bf_add_e2e_test(e2e cli/chain_load.sh ROOT)
bf_add_e2e_test(e2e cli/chain_set.sh ROOT)
bf_add_e2e_test(e2e cli/chain_update.sh ROOT)
bf_add_e2e_test(e2e cli/options_error.sh)
bf_add_e2e_test(e2e cli/ruleset.sh ROOT)

bf_add_e2e_test(e2e daemon/already_running.sh ROOT)
bf_add_e2e_test(e2e daemon/host_to_netns.sh ROOT)
bf_add_e2e_test(e2e daemon/netns_to_host.sh ROOT)
bf_add_e2e_test(e2e daemon/pin_updated_chain.sh ROOT)
bf_add_e2e_test(e2e daemon/restore_non_attached.sh ROOT)
bf_add_e2e_test(e2e daemon/sock_exists.sh ROOT)

bf_add_e2e_test(e2e matchers/icmp_code.sh)
bf_add_e2e_test(e2e matchers/icmp_type.sh)
bf_add_e2e_test(e2e matchers/icmpv6_code.sh)
bf_add_e2e_test(e2e matchers/icmpv6_type.sh)
bf_add_e2e_test(e2e matchers/ip4_daddr.sh)
bf_add_e2e_test(e2e matchers/ip4_dnet.sh)
bf_add_e2e_test(e2e matchers/ip4_proto.sh)
bf_add_e2e_test(e2e matchers/ip4_saddr.sh)
bf_add_e2e_test(e2e matchers/ip4_snet.sh)
bf_add_e2e_test(e2e matchers/ip6_daddr.sh)
bf_add_e2e_test(e2e matchers/ip6_dnet.sh)
bf_add_e2e_test(e2e matchers/ip6_nexthdr.sh)
bf_add_e2e_test(e2e matchers/ip6_saddr.sh)
bf_add_e2e_test(e2e matchers/ip6_snet.sh)
bf_add_e2e_test(e2e matchers/meta_dport.sh)
bf_add_e2e_test(e2e matchers/meta_iface.sh)
bf_add_e2e_test(e2e matchers/meta_l3_proto.sh)
bf_add_e2e_test(e2e matchers/meta_l4_proto.sh)
bf_add_e2e_test(e2e matchers/meta_mark.sh)
bf_add_e2e_test(e2e matchers/meta_probability.sh)
bf_add_e2e_test(e2e matchers/meta_sport.sh)
bf_add_e2e_test(e2e matchers/set.sh)
bf_add_e2e_test(e2e matchers/named_set.sh)
bf_add_e2e_test(e2e matchers/tcp_flags.sh)
bf_add_e2e_test(e2e matchers/tcp_dport.sh)
bf_add_e2e_test(e2e matchers/tcp_sport.sh)
bf_add_e2e_test(e2e matchers/udp_dport.sh)
bf_add_e2e_test(e2e matchers/udp_sport.sh)

bf_add_e2e_test(e2e rules/action_order.sh ROOT)
bf_add_e2e_test(e2e rules/icmp_tc.sh ROOT)
bf_add_e2e_test(e2e rules/icmp_xdp.sh ROOT)
bf_add_e2e_test(e2e rules/log.sh ROOT)
bf_add_e2e_test(e2e rules/mark.sh ROOT)

bf_add_e2e_test(e2e rulesets/rulesets.sh ROOT)

