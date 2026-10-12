/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <cstring>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpf/libbpf.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/runtime.h>
}

namespace
{

constexpr uint8_t kTransportLog = BF_FLAG(BF_LOG_OPT_TRANSPORT);

/**
 * Verify the transport header is only logged for packets which have one: a
 * packet without an L4 header must not log the previous packet's.
 */
static void transportHeader(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("test_log_headers", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), kTransportLog,
                              {bf::Matcher::alwaysMatch()}));

    fd = bf_chain_logs_fd("test_log_headers");
    assert_true(fd >= 0);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    // TCP: the transport header is logged
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(kTransportLog, capture.entries.back().pkt.headers);

    // GRE isn't parsed by bpfilter: no transport header
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::GRE {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(0, capture.entries.back().pkt.headers);

    bft_assert_counter_eq("test_log_headers", 0, 2, -1);

    ring_buffer__free(rb);
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
        cmocka_unit_test_setup_teardown(transportHeader, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    r = cmocka_run_group_tests(tests, nullptr, nullptr);
    bf_ctx_teardown();

    return r;
}
