/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <benchmark/benchmark.h>
#include <cerrno>
#include <cstring>
#include <exception>
#include <span>
#include <unistd.h>

#include "benchmark.hpp"

namespace
{
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
}

BENCHMARK(firstRuleDropCounter);

void dropAfterXRules(::benchmark::State &state)
{
    ::bf::Chain chain(::bf::config.bfcli);
    chain.repeat("rule meta.l3_proto ipv4 counter ACCEPT", state.range(0));
    chain.apply();
    auto prog = chain.getProgram();

    benchLoop(state)
    {
        if (prog.run(::bf::CGROUP_DROP, ::bf::pkt_local_ip6_tcp) < 0)
            state.SkipWithError("benchmark run failed");
    }
}

BENCHMARK(dropAfterXRules)
    ->Arg(0)
    ->Arg(8)
    ->Arg(16)
    ->Arg(32)
    ->Arg(64)
    ->Arg(128)
    ->Arg(256)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(2048);
} // namespace

int main(int argc, char *argv[])
{
    if (geteuid() != 0) {
        err("the benchmark should be run as root");
        return -EPERM;
    }

    if (::bf::parseArgs(std::span<char *>(argv, argc)) < 0)
        return -1;

    ::benchmark::Initialize(&argc, argv, nullptr);

    try {
        auto daemon = bf::Daemon(
            ::bf::config.bpfilter,
            bf::Daemon::Options().transient().noIptables().noNftables());
        ::benchmark::RunSpecifiedBenchmarks();
    } catch (const ::std::exception &e) {
        err("failed to run benchmark: {}", e.what());
        return -1;
    }

    return 0;
}
