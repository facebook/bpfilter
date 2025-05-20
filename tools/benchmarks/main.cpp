/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <benchmark/benchmark.h>
#include <cerrno>
#include <cstring>
#include <exception>
#include <format>
#include <span>
#include <unistd.h>

#include "benchmark.hpp"

namespace
{

void loadChainLargeSet(::benchmark::State &state)
{
    ::bf::Chain chain(::bf::config.bfcli);

    chain.insertRuleIPv4Set(state.range(0));

    for (auto _: state) {
        chain.apply();
    }
}

BENCHMARK(loadChainLargeSet)
    ->Arg(10000)
    ->Arg(100000)
    ->Iterations(10)
    ->Unit(benchmark::kMillisecond);

void firstRuleDropCounter(::benchmark::State &state)
{
    ::bf::Chain chain(::bf::config.bfcli);
    chain << "rule meta.l3_proto ipv6 counter DROP";
    chain.apply();
    auto prog = chain.getProgram();

    benchLoop(state)
    {
        if (prog.run(::bf::CGROUP_DROP, ::bf::pkt_local_ip6_tcp) < 0)
            state.SkipWithError("benchmark run failed");
    }

    state.counters["nInsn"] = prog.nInsn();
}

BENCHMARK(firstRuleDropCounter);

void dropAfterXRules(::benchmark::State &state)
{
    ::bf::Chain chain(::bf::config.bfcli);

    for (int i = 0; i < state.range(0); ++i)
        chain << std::format("rule meta.dport {} counter ACCEPT", i + 1);

    chain.apply();
    auto prog = chain.getProgram();

    benchLoop(state)
    {
        if (prog.run(::bf::CGROUP_DROP, ::bf::pkt_local_ip6_tcp) < 0)
            state.SkipWithError("benchmark run failed");
    }

    state.counters["nInsn"] = prog.nInsn();
}

BENCHMARK(dropAfterXRules)
    ->Arg(8)
    ->Arg(32)
    ->Arg(128)
    ->Arg(512)
    ->Arg(2048);
} // namespace

void adhocBenchmark(::benchmark::State &state, const ::std::string &ruleset)
{
    ::bf::Chain chain(::bf::config.bfcli);
    chain.repeat(ruleset, ::bf::config.adhocRepeat);
    chain.apply();
    auto prog = chain.getProgram();

    benchLoop(state)
    {
        if (prog.run(::bf::CGROUP_DROP, ::bf::pkt_local_ip6_tcp) < 0)
            state.SkipWithError("benchmark run failed");
    }

    state.counters["nInsn"] = prog.nInsn();
}

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

    ::benchmark::Initialize(&argc, argv, nullptr);

    if (!::bf::config.adhoc)
        ::bf::restorePermissions(::bf::config.outfile);

    if (::bf::config.adhoc) {
        ::benchmark::RegisterBenchmark("bf_adhoc", adhocBenchmark,
                                       *::bf::config.adhoc);
    }

    try {
        if (::bf::config.runDaemon) {
            auto daemon = bf::Daemon(
                ::bf::config.bpfilter,
                bf::Daemon::Options().transient().noIptables().noNftables());
            ::benchmark::RunSpecifiedBenchmarks();
        } else {
            ::benchmark::RunSpecifiedBenchmarks();
        }
    } catch (const ::std::exception &e) {
        err("failed to run benchmark: {}", e.what());
        return -1;
    }

    ::benchmark::Shutdown();

    return 0;
}
