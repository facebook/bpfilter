/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <array>
#include <bpf/bpf.h>
#include <cstdint>
#include <format> // NOLINT: used by the logging macros
#include <git2/types.h>
#include <initializer_list>
#include <iostream> // NOLINT: used by the logging macros
#include <optional>
#include <span>
#include <string>
#include <sys/types.h> // NOLINT: for pid_t
#include <vector>
#include <bpfilter/bpfilter.h>
#include <unistd.h>
#include <bpf/libbpf_common.h>
#include <linux/bpf.h>
#include <cstdio>

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

extern const std::array<uint8_t, 42> pkt_local_ip4_icmp;
extern const std::array<uint8_t, 54> pkt_local_ip4_tcp;
extern const std::array<uint8_t, 90> pkt_remote_ip6_eh;

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

int disableASLR(char **argv);
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

    std::string stdout();
    std::string stderr();

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

class OldChain
{
public:
    OldChain(::std::string bin = "bfcli", ::std::string name = "bf_bench");
    OldChain(::std::initializer_list<::std::string> rules);

    OldChain &operator<<(const ::std::string &rule);
    OldChain &repeat(const ::std::string &rule, ::std::size_t count);
    void insertRuleIPv4Set(unsigned int nIps);
    int apply();
    [[nodiscard]] Program getProgram() const;

private:
    ::std::string bin_;
    ::std::string name_;
    ::std::vector<::std::string> rules_;
};

namespace test
{

struct ProgRunStats
{
    uint32_t retval;
    uint32_t duration;
    uint32_t repeat;

    ProgRunStats(bpf_test_run_opts stats): retval{stats.retval}, duration{stats.duration}, repeat{static_cast<uint32_t>(stats.repeat)} {}
};

class Program
{
private:
    int _fd;
    size_t _nInsn;

public:
    Program(std::string chainName)
    {
        _fd = bf_chain_prog_fd(chainName.c_str());
        if (_fd < 0)
            throw std::runtime_error("failed to request BPF program file descriptor");
    }

    ~Program()
    {
        close(_fd);
    }

    Program(Program &other) = delete;
    Program(Program &&other) = delete;
    Program &operator=(Program &other) = delete;
    Program &operator=(Program &&other) = delete;

    [[nodiscard]] ::std::size_t nInsn() const
    {
        struct bpf_prog_info prog_info = {};
        uint32_t prog_info_len = sizeof(prog_info);
        int r;

        r = bpf_prog_get_info_by_fd(_fd, &prog_info, &prog_info_len);
        if (r < 0)
            throw std::runtime_error("failed to get BPF program info");

        return prog_info.xlated_prog_len / sizeof(struct bpf_insn);
    }

    [[nodiscard]] ProgRunStats run(const std::span<const uint8_t> &pkt) const
    {
        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = (const void *)pkt.data(),
                .data_size_in = (uint32_t)pkt.size(), .repeat = progRunRepeat);

        const int r = bpf_prog_test_run_opts(_fd, &opts);
        if (r < 0)
            throw std::runtime_error("failed to run BPF program");

        return ProgRunStats(opts);
    }
};

}

} // namespace bf
