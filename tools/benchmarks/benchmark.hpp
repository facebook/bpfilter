/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <format> // NOLINT: used by the logging macros
#include <git2/types.h>
#include <initializer_list>
#include <iostream> // NOLINT: used by the logging macros
#include <optional>
#include <span>
#include <string>
#include <sys/types.h> // NOLINT: for pid_t
#include <vector>

#pragma once

namespace bf
{

extern const int CGROUP_DROP;
extern const int CGROUP_ACCEPT;

/**
 * Dummy network packet, created using Python's @c scapy and the following
 * definition:
 *
 *  Ether(src=0x01, dst=0x02)/
 *  IPv6(src='::1', dst='::2')/
 *  TCP(sport=31337, dport=31415, flags='S')
 *
 * This packet defines an Ethernet, IPv6, and TCP header.
 */
extern const std::array<uint8_t, 80> pkt_local_ip6_tcp;

/**
 * Number of iterations to run the program for.
 *
 * Google Benchmark will run each benchmark for a specific duration, so the
 * fastest functions will run for more iterations. This is problematic as
 * @c BPF_PROG_TEST_RUN requires a number of iterations. To solve this, we use
 * @c KeepRunningBatch in order to find out if we can run the benchmark for
 * @c progRunRepeat more iterations.
 *
 * @c progRunRepeat is big enough to have meaningful benchmark results and
 * reduce syscall overhead, while being small enough to avoid blocking the
 * system too long with longer benchmarks.
 */
extern const int progRunRepeat;

#define abort(fmt, ...)                                                        \
    throw ::std::runtime_error(::std::format(fmt, ##__VA_ARGS__))

#define err(fmt, ...)                                                          \
    do {                                                                       \
        ::std::cerr << ::std::format("ERROR: " fmt "\n", ##__VA_ARGS__);       \
    } while (0)

#define info(fmt, ...)                                                         \
    do {                                                                       \
        ::std::cout << ::std::format(fmt "\n", ##__VA_ARGS__);                 \
    } while (0)

/**
 * Loop used to run the benchmark.
 *
 * Use this macro to loop over the state automatically.
 */
#define benchLoop(state) while ((state).KeepRunningBatch(::bf::progRunRepeat))

struct Config
{
public:
    ::std::string bfcli = "bfcli";
    ::std::string bpfilter = "bpfilter";
    ::std::string srcdir = ".";
    ::std::string outfile = "results.json";
    ::std::string gitrev = "<unknown>";
    ::std::optional<::std::string> adhoc;
    int adhocRepeat = 1;
    const ::std::string adhocBenchName = "bf_adhoc";
    int64_t gitdate = 0;
    bool runDaemon = true;

    Config() noexcept = default;
};

extern Config config;

int setup(std::span<char *> args);
void restorePermissions(::std::string outfile);

class Sources
{
public:
    Sources(::std::string path);
    Sources(Sources &other) = delete;
    Sources(Sources &&other) = delete;
    ~Sources();

    Sources &operator=(Sources &other) = delete;
    Sources &operator=(Sources &&other) = delete;

    [[nodiscard]] ::std::string getLastCommitHash() const;
    [[nodiscard]] int64_t getLastCommitTime() const;
    [[nodiscard]] bool isDirty() const;

private:
    ::std::string path_;
    git_repository *repo_ = nullptr;
};

class Fd
{
public:
    Fd(int fd = -1);
    Fd(Fd &other) = delete;
    Fd(Fd &&other) noexcept(false);
    ~Fd() noexcept(false);

    Fd &operator=(Fd &other) = delete;
    Fd &operator=(Fd &&other) noexcept(false);

    [[nodiscard]] int get() const;
    int close();

private:
    int fd_ = -1;
};

class Daemon
{
public:
    class Options
    {
    public:
        Options &transient();
        Options &noCli();
        Options &noIptables();
        Options &noNftables();
        Options &bufferLen(::std::size_t len);
        Options &verbose(const ::std::string &component);
        [[nodiscard]] ::std::vector<::std::string> get() const;

    private:
        ::std::vector<::std::string> options_;
    };

    Daemon(::std::string path = "bpfilter", Options options = Options());
    Daemon(Daemon &other) = delete;
    Daemon(Daemon &&other) noexcept(false);
    ~Daemon() noexcept(false);

    Daemon &operator=(Daemon &other) = delete;
    Daemon &operator=(Daemon &&other) noexcept(false);

private:
    ::std::string path_;
    Options options_;
    std::optional<pid_t> pid_;
    Fd stdoutFd_;
    Fd stderrFd_;

    [[nodiscard]] int start();
    int stop();
};

class Program
{
public:
    Program(std::string name);
    Program(Program &other) = delete;
    Program(Program &&other) noexcept(false);
    ~Program() noexcept(false);

    Program &operator=(Program &other) = delete;
    Program &operator=(Program &&other) noexcept(false);

    [[nodiscard]] ::std::size_t nInsn() const;
    [[nodiscard]] int run(int expect,
                          const std::span<const uint8_t> &pkt) const;
    int close();

private:
    ::std::string name_;
    int fd_ = -1;

    int open();
};

class Chain
{
public:
    Chain(::std::string bin = "bfcli", ::std::string name = "bf_bench");
    Chain(::std::initializer_list<::std::string> rules);

    Chain &operator<<(const ::std::string &rule);
    Chain &repeat(const ::std::string &rule, ::std::size_t count);
    int apply();
    [[nodiscard]] Program getProgram() const;

private:
    ::std::string bin_;
    ::std::string name_;
    ::std::vector<::std::string> rules_;
};

} // namespace bf
