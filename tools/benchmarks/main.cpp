/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <benchmark/benchmark.h>
#include <cerrno>
#include <cstdint>
#include <exception>
#include <format>
#include <span>
#include <unistd.h>
#include <linux/bpf.h>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
#include <cstdio>

extern "C" {
#include <bpfilter/bpfilter.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>
}

#include "benchmark.hpp"

#include "Rule.hpp"
#include "Chain.hpp"
#include "Matcher.hpp"
#include "Set.hpp"

namespace
{

using bf::Chain;
using bf::Rule;
using bf::Matcher;
using bf::Set;

std::vector<uint8_t> uint32ToIp4(uint32_t val)
{
    return {
        static_cast<uint8_t>(val >> 24),
        static_cast<uint8_t>(val >> 16),
        static_cast<uint8_t>(val >> 8),
        static_cast<uint8_t>(val)
    };
}

std::vector<uint8_t> uint32ToIp6(uint32_t val)
{
    return {
        static_cast<uint8_t>(val >> 24),
        static_cast<uint8_t>(val >> 16),
        static_cast<uint8_t>(val >> 8),
        static_cast<uint8_t>(val),
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
}

void chain_policy_c(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_DROP);

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("chain policy, with counter");
}
BENCHMARK(chain_policy_c);

void single_rule__ip4_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ, {0x7f, 0x02, 0x0a, 0x0a}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip4.saddr");
}
BENCHMARK(single_rule__ip4_saddr);

void multiple_rules__ip4_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i) {
        chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
            Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ, uint32ToIp4(i)),
        });
    }

    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ, {0x7f, 0x02, 0x0a, 0x0a}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel(std::format("{} rules, ip4.saddr", nrules));
}
BENCHMARK(multiple_rules__ip4_saddr)
    ->Arg(8)
    ->Arg(32)
    ->Arg(128)
    ->Arg(512)
    ->Arg(2048);

void single_rule__ip4_saddr__x_elem_set(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    Set s = Set({BF_MATCHER_IP4_SADDR});

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i)
        s << uint32ToIp4(i);

    s << std::vector<uint8_t>{0x7f, 0x02, 0x0a, 0x0a};

    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_SET, BF_MATCHER_IN, {0, 0, 0, 0}),
    });

    chain << s;

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel(std::format("1 rule, ip4.saddr, {} elements set", nrules));
}
BENCHMARK(single_rule__ip4_saddr__x_elem_set)
    ->Arg(1 << 16)
    ->Arg(1 << 18)
    ->Arg(1 << 20);

void single_rule__ip4_saddr_c(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, true, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ, {0x7f, 0x02, 0x0a, 0x0a}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip4.saddr, counter");
}
BENCHMARK(single_rule__ip4_saddr_c);

void single_rule__ip4_saddr_l(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, bf::RuleLogBitset().set(BF_PKTHDR_LINK), std::vector<Matcher>{
        Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ, {0x7f, 0x02, 0x0a, 0x0a}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip4.saddr, log link");
}
BENCHMARK(single_rule__ip4_saddr_l);

void single_rule__ip6_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

        while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip6.saddr");
}
BENCHMARK(single_rule__ip6_saddr);

void multiple_rules__ip6_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i) {
        chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
            Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ, uint32ToIp6(i)),
        });
    }

    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel(std::format("{} rules, ip6.saddr", nrules));
}
BENCHMARK(multiple_rules__ip6_saddr)
    ->Arg(8)
    ->Arg(32)
    ->Arg(128)
    ->Arg(512)
    ->Arg(2048);

void single_rule__ip6_saddr__x_elem_set(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    Set s = Set({BF_MATCHER_IP6_SADDR});

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i)
        s << uint32ToIp6(i);

    s << std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_SET, BF_MATCHER_IN, {0, 0, 0, 0}),
    });

    chain << s;

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel(std::format("1 rule, ip6.saddr, {} elements set", nrules));
}
BENCHMARK(single_rule__ip6_saddr__x_elem_set)
    ->Arg(1 << 16)
    ->Arg(1 << 18)
    ->Arg(1 << 20);

void single_rule__ip6_saddr_c(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, true, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip6.saddr, counter");
}
BENCHMARK(single_rule__ip6_saddr_c);

void single_rule__ip6_saddr_l(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, bf::RuleLogBitset().set(BF_PKTHDR_LINK), std::vector<Matcher>{
        Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip6.saddr, log link");
}
BENCHMARK(single_rule__ip6_saddr_l);

void single_rule__ip6_nexthdr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_IP6_NEXTHDR, BF_MATCHER_EQ, {0x00, 0x00}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

        while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_remote_ip6_eh);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip6.nexthdr");
}
BENCHMARK(single_rule__ip6_nexthdr);

void single_rule__meta_sport_eq(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_META_SPORT, BF_MATCHER_EQ, {0x00, 0x17}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, meta.sport eq");
}
BENCHMARK(single_rule__meta_sport_eq);

void single_rule__meta_sport_range(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_META_SPORT, BF_MATCHER_RANGE, {0x16, 0x00, 0x18, 0x00}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, meta.sport range");
}
BENCHMARK(single_rule__meta_sport_range);

void single_rule__tcp_sport(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, false, {}, std::vector<Matcher>{
        Matcher(BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ, {0x00, 0x17}),
    });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bf::test::Program(chain.name());

    while (state.KeepRunningBatch(::bf::progRunRepeat)) {
        auto stats = prog.run(::bf::pkt_local_ip4_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime((double)stats.duration * stats.repeat);
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, tcp.sport");
}
BENCHMARK(single_rule__tcp_sport);

} // namespace

int main(int argc, char *argv[])
{
    if (geteuid() != 0) {
        err("the benchmark should be run as root");
        return -EPERM;
    }

    if (::bf::disableASLR(argv) < 0)
        return -1;

    if (::bf::setup(std::span<char *>(argv, argc)) < 0)
        return -1;

    ::bf::restorePermissions(::bf::config.outfile);

    ::std::optional<bf::Daemon> daemon;
    if (::bf::config.runDaemon) {
     daemon = bf::Daemon(
        ::bf::config.bpfilter,
        bf::Daemon::Options().transient().noIptables().noNftables());
    }

    try {
        ::benchmark::RunSpecifiedBenchmarks();
    } catch (const ::std::exception &e) {
        if (daemon) {
            std::cout << daemon->stderr();
        }
        err("failed to run benchmark: {}", e.what());
        return -1;
    }

    ::benchmark::Shutdown();

    return 0;
}
