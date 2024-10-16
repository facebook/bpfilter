/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "benchmark.hpp"

#include <linux/bpf.h>

#include <argp.h>
#include <array>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <initializer_list>
#include <iostream> // NOLINT
#include <optional>
#include <signal.h> // NOLINT: otherwise kill() is not found
#include <span>
#include <stdlib.h> // NOLINT
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

namespace benchmark
{
extern bool FLAGS_benchmark_list_tests;
extern std::string FLAGS_benchmark_filter;
extern std::string FLAGS_benchmark_min_time;
extern double FLAGS_benchmark_min_warmup_time;
extern int FLAGS_benchmark_repetitions;
extern bool FLAGS_benchmark_dry_run;
extern bool FLAGS_benchmark_enable_random_interleaving;
extern bool FLAGS_benchmark_report_aggregates_only;
extern bool FLAGS_benchmark_display_aggregates_only;
extern std::string FLAGS_benchmark_format;
extern std::string FLAGS_benchmark_out;
extern std::string FLAGS_benchmark_out_format;
extern std::string FLAGS_benchmark_color;
extern bool FLAGS_benchmark_counters_tabular;
extern std::string FLAGS_benchmark_perf_counters;
extern std::string FLAGS_benchmark_time_unit;
extern int FLAGS_v;
} // namespace benchmark

namespace bf
{
using TimePoint = std::chrono::steady_clock::time_point;
using time = std::chrono::steady_clock;
using seconds = std::chrono::seconds;

constexpr int CGROUP_DROP = 0;
constexpr int CGROUP_ACCEPT = 1;

// Ether(src=0x01, dst=0x02)
// IPv6(src='::1', dst='::2')
// TCP(sport=31337, dport=31415, flags='S')
constexpr std::array<uint8_t, 80> pkt_local_ip6_tcp {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7a,
    0x69, 0x7a, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0x20, 0x00, 0x9a, 0xbf, 0x00, 0x00};

constexpr int progRunRepeat = 1000000;

Config config = {};

namespace
{
constexpr int waitForDaemonTimeoutS = 5;
constexpr int waitForDaemonSleepMs = 10;

constexpr std::array<struct argp_option, 4> options {{
    {"cli", 'c', "CLI", 0,
     "Path to the bfcli binary. Default to 'bfcli' in $PATH.", 0},
    {"daemon", 'd', "DAEMON", 0,
     "Path to the bpfilter binary. Default to 'bpfilter' in $PATH.", 0},
    {"output", 'o', "OUTPUT_FILE", 0,
     "Path to the JSON file to write the results to.", 0},
    {nullptr},
}};

inline char *errStr(int value)
{
    return ::std::strerror(::std::abs(value));
}

int optsParser(int key, char *arg, struct ::argp_state *state)
{
    auto *config = static_cast<Config *>(state->input);
    int r;

    switch (key) {
    case 'c':
        config->bfcli = std::string(arg);
        break;
    case 'd':
        config->bpfilter = std::string(arg);
        break;
    case 'o':
        config->output_file.emplace(arg);
        ::benchmark::FLAGS_benchmark_out = arg;
        ::benchmark::FLAGS_benchmark_out_format = "json";
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int setFdNonBlock(Fd &fd)
{
    const int flags = fcntl(fd.get(), F_GETFL, 0);
    if (flags < 0) {
        err("failed to get current flags for FD {}: {}", fd.get(),
            errStr(errno));
        return -errno;
    }

    return fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK);
}

::std::optional<::std::string> readFd(Fd &fd)
{
    ssize_t len;
    std::array<char, 1024> buffer;
    ::std::string data;

    while ((len = read(fd.get(), buffer.data(), buffer.size())) >= 0)
        data += ::std::string(::std::begin(buffer), ::std::end(buffer));

    if (len < 0 && errno != EAGAIN)
        err("failed to read from file descriptor: {}", errStr(errno));

    return data;
}

int exec(const ::std::string &bin, const ::std::vector<::std::string> &args,
         Fd &stdoutFd, Fd &stderrFd)
{
    std::array<int, 2> stdout_pipe;
    std::array<int, 2> stderr_pipe;
    pid_t pid;

    // Format the argv[] array properly
    std::vector<const char *> args_;
    args_.push_back(bin.c_str());
    for (const auto &arg: args)
        args_.push_back(arg.c_str());
    args_.push_back(nullptr);

    if (pipe(stdout_pipe.data()) != 0 || pipe(stderr_pipe.data()) != 0) {
        err("failed to create pipes for '{}'", bin);
        return -EINVAL;
    }

    pid = fork();
    if (pid < 0) {
        err("failed to fork '{}': {}", bin, errStr(errno));
        return -errno;
    }

    // If we're the child
    if (pid == 0) {
        int r;

        r = dup2(stdout_pipe[1], STDOUT_FILENO);
        if (r < 0) {
            err("failed to duplicate pipe to STDOUT_FILENOP for '{}': {}", bin,
                errStr(errno));
            return -errno;
        }

        r = dup2(stderr_pipe[1], STDERR_FILENO);
        if (r < 0) {
            err("failed to duplicate pipe to STDERR_FILENO for '{}': {}", bin,
                errStr(errno));
            return -errno;
        }

        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        (void)execvp(bin.c_str(), (char * const *)(args_.data()));

        // If execvp returns, an error occurred
        err("execvp() failed to '{}': {}", bin, errStr(errno));
        return -errno;
    }

    // Send back the pipes FD and PID to the parent
    stdoutFd = std::move(Fd(stdout_pipe[0]));
    stderrFd = std::move(Fd(stderr_pipe[0]));

    return pid;
}

::std::tuple<int, ::std::string, ::std::string>
run(::std::string bin, const ::std::vector<::std::string> &args)
{
    Fd stdoutFd, stderrFd;

    int pid = exec(bin, args, stdoutFd, stderrFd);
    if (pid < 0) {
        err("failed to exec '{}': {}", bin, errStr(pid));
        return {pid, {}, {}};
    }

    if (setFdNonBlock(stdoutFd) < 0 || setFdNonBlock(stderrFd) < 0) {
        err("failed to set FD non-blocking for '{}': {}", bin, errStr(errno));
        return {-errno, {}, {}};
    }

    int status;
    const int r = waitpid(pid, &status, 0);
    if (r < 0) {
        err("failed to wait for PID {}: {}", pid, errStr(errno));
        return {-errno, {}, {}};
    }

    const auto logOut = readFd(stdoutFd);
    const auto logErr = readFd(stderrFd);
    const ::std::string noLog;

    return {WEXITSTATUS(status), logOut ? *logOut : noLog,
            logErr ? *logErr : noLog};
}
} // namespace

int parseArgs(std::span<char *> args)
{
    const struct argp argp = {options.data(), optsParser};

    const int r = argp_parse(&argp, static_cast<int>(args.size()), args.data(),
                             0, nullptr, &::bf::config);
    if (r != 0) {
        err("failed to parse command line arguments: {}", errStr(r));
        return r;
    }

    info("Using:");
    info("  bfcli: {}", ::bf::args.bfcli);
    info("  bpfilter: {}", ::bf::args.bpfilter);

    if (::bf::args.output_file)
        info("  output_file: {}", *::bf::args.output_file);

    return 0;
}

Fd::Fd(int fd):
    fd_ {fd}
{}

Fd::Fd(Fd &&other) noexcept(false)
{
    if (fd_ != -1)
        abort("calling ::bf::Fd(Fd &&) on an open file descriptor!");

    fd_ = other.fd_;
    other.fd_ = -1;
}

Fd &Fd::operator=(Fd &&other) noexcept(false)
{
    if (fd_ != -1)
        abort("calling ::bf::Fd::operator=(Fd &&) on an open file descriptor!");

    fd_ = other.fd_;
    other.fd_ = -1;

    return *this;
}

Fd::~Fd() noexcept(false)
{
    if (close() < 0)
        abort("failed to close ::bf::Fd");
}

int Fd::get() const
{
    return fd_;
}

int Fd::close()
{
    if (fd_ == -1)
        return 0;

    if (::close(fd_) < 0) {
        err("failed to close ::bf::Fd file descriptor: {}", errStr(errno));
        return -errno;
    }

    fd_ = -1;

    return 0;
}

Daemon::Options &Daemon::Options::transient()
{
    options_.emplace_back("--transient");
    return *this;
}

Daemon::Options &Daemon::Options::noCli()
{
    options_.emplace_back("--no-cli");
    return *this;
}

Daemon::Options &Daemon::Options::noIptables()
{
    options_.emplace_back("--no-iptables");
    return *this;
}

Daemon::Options &Daemon::Options::noNftables()
{
    options_.emplace_back("--no-nftables");
    return *this;
}

Daemon::Options &Daemon::Options::bufferLen(::std::size_t len)
{
    options_.emplace_back("--buffer-len");
    options_.emplace_back(::std::to_string(len));
    return *this;
}

Daemon::Options &Daemon::Options::verbose(const ::std::string &component)
{
    options_.emplace_back("--verbose");
    options_.emplace_back(component);
    return *this;
}

::std::vector<::std::string> Daemon::Options::get() const
{
    return options_;
}

Daemon::Daemon(::std::string path, Options options):
    path_ {::std::move(path)},
    options_ {::std::move(options)}
{
    if (start() < 0)
        abort("failed to start bpfilter");
}

Daemon::Daemon(Daemon &&other) noexcept(false)
{
    if (pid_)
        abort("calling ::bf::Daemon(::bf::Daemon &&) on an active daemon!");

    other.pid_.swap(pid_);
    stdoutFd_ = ::std::move(other.stdoutFd_);
    stderrFd_ = ::std::move(other.stderrFd_);
}

Daemon &Daemon::operator=(Daemon &&other) noexcept(false)
{
    if (pid_)
        abort(
            "calling ::bf::Daemon::operator=(::fd::Daemon &&) on an active daemon!");

    other.pid_.swap(pid_);
    stdoutFd_ = ::std::move(other.stdoutFd_);
    stderrFd_ = ::std::move(other.stderrFd_);

    return *this;
}

Daemon::~Daemon() noexcept(false)
{
    if (stop() < 0)
        abort("failed to stop bpfilter");
}

int Daemon::start()
{
    Fd stdoutFd, stderrFd;
    int pid, r;

    if (pid_)
        abort("calling ::bf::Daemon::start() on an active daemon!");

    pid = exec(path_, options_.get(), stdoutFd, stderrFd);
    if (pid < 0) {
        err("failed to start the daemon: {}", errStr(pid));
        return pid;
    }

    if ((r = setFdNonBlock(stdoutFd)) < 0) {
        err("failed to set non-blocking flag to the daemon's stdout FD: {}",
            errStr(r));
        return r;
    }

    if ((r = setFdNonBlock(stderrFd)) < 0) {
        err("failed to set non-blocking flag to the daemon's stderr FD: {}",
            errStr(r));
        return r;
    }

    const TimePoint begin = time::now();

    while (true) {
        int status;

        r = waitpid(pid, &status, WNOHANG);
        if (r == -1) {
            err("failed to wait on the deamon's PID {}: {}", pid,
                errStr(errno));
            return -errno;
        }
        if (r != 0) {
            auto errLogs = readFd(stderrFd);
            err("daemon seems to be dead! Err logs:\n{}",
                errLogs ? *errLogs : "<no logs>");
            return -ENOENT;
        }

        auto data = readFd(stderrFd);
        if (data &&
            data->find("waiting for requests...") != ::std::string::npos)
            break;

        if (std::chrono::duration_cast<seconds>(time::now() - begin).count() >
            waitForDaemonTimeoutS) {
            // Let's try to stop it just in case
            kill(pid, SIGINT);
            err("daemon is not showing up after {} seconds, aborting",
                waitForDaemonTimeoutS);
            return -EIO;
        }

        // Wait a bit for the daemon to be ready
        ::std::this_thread::sleep_for(
            std::chrono::milliseconds(waitForDaemonSleepMs));
    }

    pid_ = ::std::optional<int>(pid);
    stdoutFd_ = std::move(stdoutFd);
    stderrFd_ = std::move(stderrFd);

    return 0;
}

int Daemon::stop()
{
    if (!pid_)
        return 0;

    int r = kill(*pid_, SIGINT);
    if (r < 0) {
        err("failed to send SIGINT signal to the daemon: {}", errStr(errno));
        return -errno;
    }

    int status;
    r = waitpid(*pid_, &status, 0);
    if (r < 0) {
        err("can't wait on the daemon: {}", errStr(errno));
        return -errno;
    }

    return 0;
}

Program::Program(std::string name):
    name_ {::std::move(name)}
{
    if (open() < 0)
        abort("failed to open BPF program '{}'", name_);
}

Program::Program(Program &&other) noexcept(false)
{
    if (fd_ != -1) {
        abort("calling ::bf::Program(::bf::Program &&) on an open program!");
    }

    fd_ = other.fd_;
    other.fd_ = -1;
}

Program &Program::operator=(Program &&other) noexcept(false)
{
    if (fd_ != -1) {
        abort(
            "calling ::bf::Program::operator=(::bf::Program &&) on an open program!");
    }

    fd_ = other.fd_;
    other.fd_ = -1;

    return *this;
}

Program::~Program() noexcept(false)
{
    if (close() < 0)
        abort("failed to close ::bf::Program");
}

int Program::run(int expect, const std::span<const uint8_t> &pkt) const
{
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = (const void *)pkt.data(),
                .data_size_in = (uint32_t)pkt.size(), .repeat = progRunRepeat);

    const int r = bpf_prog_test_run_opts(fd_, &opts);
    if (r < 0) {
        err("BPF program test run failed: {}", errStr(r));
        return r;
    }

    if (opts.retval != expect) {
        err("unexpected test run return value: {}", opts.retval);
        return -EINVAL;
    }

    return 0;
}

int Program::close()
{
    if (fd_ == -1)
        return 0;

    if (::close(fd_) < 0) {
        err("failed to close ::bf::Program file descriptor: {}", errStr(errno));
        return -errno;
    }

    fd_ = -1;

    return 0;
}

int Program::open()
{
    uint32_t id = 0;
    int r;

    while (true) {
        r = bpf_prog_get_next_id(id, &id);
        if (r < 0) {
            err("call to bpf_prog_get_next_id() failed: {}", errStr(r));
            return r;
        }

        const int prog_fd = bpf_prog_get_fd_by_id(id);
        if (prog_fd < 0) {
            err("call to bpf_prog_get_fd_by_id() failed: {}", errStr(prog_fd));
            return prog_fd;
        }

        struct bpf_prog_info info = {};
        uint32_t len = sizeof(info);
        r = bpf_prog_get_info_by_fd(prog_fd, &info, &len);
        if (r < 0) {
            ::close(prog_fd);
            err("call to bpf_prog_get_info_by_fd() failed: {}", errStr(r));
            return r;
        }

        if (::std::string(info.name) == name_) {
            fd_ = prog_fd;
            return 0;
        }

        ::close(prog_fd);
    }

    return -ENOENT;
}

Chain::Chain(::std::string bin, ::std::string name):
    bin_ {::std::move(bin)},
    name_ {::std::move(name)}
{}

Chain::Chain(::std::initializer_list<::std::string> rules)
{
    rules_.insert(rules_.begin(), rules.begin(), rules.end());
}

Chain &Chain::operator<<(const ::std::string &rule)
{
    rules_.push_back(rule);
    return *this;
}

Chain &Chain::repeat(const ::std::string &rule, ::std::size_t count)
{
    for (::std::size_t i = 0; i < count; ++i)
        rules_.push_back(rule);

    return *this;
}

int Chain::apply()
{
    ::std::string chain = "chain BF_HOOK_CGROUP_INGRESS{cgroup=" + name_ +
                          ",name=" + name_ + ",attach=no} policy DROP ";

    for (const auto &rule: rules_)
        chain += rule + " ";

    const ::std::vector<::std::string> args {"--str", chain};

    const auto [r, out, err] = run(bin_, args);
    if (r < 0) {
        err("failed to exec '{}': {}\nError logs: {}", bin_, errStr(r), err);
        return r;
    }

    return 0;
}

Program Chain::getProgram() const
{
    return {name_};
}

} // namespace bf
