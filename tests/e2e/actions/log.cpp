/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <cerrno>
#include <cstring>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "Set.hpp"
#include "test.hpp"

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpfilter/bpfilter.h>
}

namespace
{

static uint32_t mapId(int fd)
{
    struct bpf_map_info info = {};
    uint32_t len = sizeof(info);

    assert_ok(bpf_map_get_info_by_fd(fd, &info, &len));

    return info.id;
}

static void logsFdSurvivesChainUpdate(void **state)
{
    _cleanup_close_ int fd = -1;
    _cleanup_close_ int new_fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;
    auto updated =
        bf::Chain("test_log_update", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP, std::nullopt, BF_LOG_OPT_DEFAULT,
                    {bf::Matcher::alwaysMatch()});

    (void)state;

    BFT_CHAIN_SET(bf::Chain("test_log_update", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_ACCEPT, std::nullopt,
                              BF_LOG_OPT_DEFAULT,
                              {bf::Matcher::alwaysMatch()}));

    fd = bf_chain_logs_fd("test_log_update");
    assert_fd(fd);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    assert_ok(bf_chain_update(updated.get().get()));
    bft_assert_prog_run("test_log_update", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(1, capture.entries.size());
    assert_int_equal(BF_VERDICT_DROP, capture.entries[0].verdict);

    new_fd = bf_chain_logs_fd("test_log_update");
    assert_fd(new_fd);
    assert_int_equal(mapId(fd), mapId(new_fd));

    ring_buffer__free(rb);
}

static void logsFdSurvivesSetUpdate(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;
    auto set = bf::Set({BF_MATCHER_UDP_DPORT});
    // Copies of a set share its name, as bf_chain_update_set() requires
    auto to_add = set;
    auto to_remove = set;

    (void)state;

    set << bft_port_be(53);
    BFT_CHAIN_SET(
        bf::Chain("test_log_update_set", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, std::nullopt, BF_LOG_OPT_DEFAULT,
                    {bf::Matcher::in(set)}));

    fd = bf_chain_logs_fd("test_log_update_set");
    assert_fd(fd);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    to_add << bft_port_be(5353);
    assert_ok(bf_chain_update_set("test_log_update_set", to_add.get().get(),
                                  to_remove.get().get()));
    bft_assert_prog_run("test_log_update_set", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} /
                            bft::UDP {.sport = 12345, .dport = 5353},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(1, capture.entries.size());

    ring_buffer__free(rb);
}

static void logsFdSurvivesEmptySet(void **state)
{
    _cleanup_close_ int fd = -1;
    _cleanup_close_ int empty_fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;
    auto set = bf::Set({BF_MATCHER_UDP_DPORT});
    // Copies of a set share its name, as bf_chain_update_set() requires
    auto none = set;
    auto port = set;

    (void)state;

    set << bft_port_be(53);
    port << bft_port_be(53);
    BFT_CHAIN_SET(
        bf::Chain("test_log_empty_set", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, std::nullopt, BF_LOG_OPT_DEFAULT,
                    {bf::Matcher::in(set)}));

    fd = bf_chain_logs_fd("test_log_empty_set");
    assert_fd(fd);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    /* Emptying the set disables the only logging rule: the chain doesn't log
     * anymore, but it keeps its logs buffer. */
    assert_ok(bf_chain_update_set("test_log_empty_set", none.get().get(),
                                  port.get().get()));
    bft_assert_prog_run("test_log_empty_set", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} /
                            bft::UDP {.sport = 12345, .dport = 53},
                        bft_hook_accept(BF_HOOK_XDP));
    assert_int_equal(0, ring_buffer__consume(rb));
    empty_fd = bf_chain_logs_fd("test_log_empty_set");
    assert_fd(empty_fd);
    assert_int_equal(mapId(fd), mapId(empty_fd));

    // Refilling the set enables the rule again
    assert_ok(bf_chain_update_set("test_log_empty_set", port.get().get(),
                                  none.get().get()));
    bft_assert_prog_run("test_log_empty_set", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} /
                            bft::UDP {.sport = 12345, .dport = 53},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(1, capture.entries.size());

    ring_buffer__free(rb);
}

static void logsBufferRemovedWithoutLoggingRule(void **state)
{
    auto updated = bf::Chain("test_log_removed", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                   << bf::Rule(BF_VERDICT_DROP, std::nullopt, 0,
                               {bf::Matcher::alwaysMatch()});

    (void)state;

    BFT_CHAIN_SET(bf::Chain("test_log_removed", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, std::nullopt, BF_LOG_OPT_DEFAULT,
                              {bf::Matcher::alwaysMatch()}));

    assert_ok(bf_chain_update(updated.get().get()));
    assert_int_equal(-ENOENT, bf_chain_logs_fd("test_log_removed"));
}

} // namespace

int main()
{
    int r = bf_ctx_setup(false, "/sys/fs/bpf", 0);
    if (r != 0) {
        bf_err("failed to setup bpfilter context: %s", std::strerror(-r));
        return 1;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(logsFdSurvivesChainUpdate,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(logsFdSurvivesSetUpdate,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(logsFdSurvivesEmptySet,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(logsBufferRemovedWithoutLoggingRule,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    r = cmocka_run_group_tests(tests, nullptr, nullptr);
    bf_ctx_teardown();

    return r;
}
