/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <array>
#include <benchmark/benchmark.h>
#include <bpf/bpf.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

#define _log_impl(stream, prefix, fmt, ...)                                    \
    do {                                                                       \
        using ::std::cerr;                                                     \
        using ::std::cout;                                                     \
        stream << ::std::format("{}" fmt, prefix, ##__VA_ARGS__)               \
               << ::std::endl;                                                 \
    } while (0)

#define abort(fmt, ...)                                                        \
    throw ::std::runtime_error(::std::format(fmt, ##__VA_ARGS__))

#define err(fmt, ...) _log_impl(cerr, "ERROR: ", fmt, ##__VA_ARGS__)
#define info(fmt, ...) _log_impl(cout, "", fmt, ##__VA_ARGS__)

namespace bf
{

using TimePoint = std::chrono::steady_clock::time_point;
using time = std::chrono::steady_clock;
using seconds = std::chrono::seconds;

static const struct argp_option options[] = {
    {"cli", 'c', "CLI", 0,
     "Path to the bfcli binary. Default to 'bfcli' in $PATH.", 0},
    {"daemon", 'd', "DAEMON", 0,
     "Path to the bpfilter binary. Default to 'bpfilter' in $PATH.", 0},
    {0},
};

struct Args
{
    ::std::string bfcli = "bfcli";
    ::std::string bpfilter = "bpfilter";
};

Args args;

constexpr int progRunRepeat = 1000000;

char *errStr(int v)
{
    return ::std::strerror(v >= 0 ?: -v);
}

static error_t optsParser(int key, char *arg, struct argp_state *state)
{
    struct Args *args = static_cast<struct Args *>(state->input);
    int r;

    switch (key) {
    case 'c':
        args->bfcli = std::string(arg);
        break;
    case 'd':
        args->bpfilter = std::string(arg);
        break;
    default:
        // Ignore unknown arguments, as Google Benchmark has their own
        return 0;
    }

    return 0;
}

class Fd
{
    public:
    Fd(int fd = -1):
        fd_ {fd}
    {}

    Fd(Fd &other) = delete;

    Fd(Fd &&other)
    {
        if (fd_ != -1)
            abort("calling ::bf::Fd(Fd &&) on an open file descriptor!");

        fd_ = other.fd_;
        other.fd_ = -1;
    }

    Fd &operator=(Fd &other) = delete;

    Fd &operator=(Fd &&other)
    {
        if (fd_ != -1)
            abort(
                "calling ::bf::Fd::operator=(Fd &&) on an open file descriptor!");

        fd_ = other.fd_;
        other.fd_ = -1;

        return *this;
    }

    ~Fd() noexcept(false)
    {
        if (close() < 0)
            abort("failed to close ::bf::Fd");
    }

    int get() const
    {
        return fd_;
    }

    int close()
    {
        if (fd_ == -1)
            return 0;

        int r = ::close(fd_);
        if (r < 0) {
            err("failed to close ::bf::Fd file descriptor: {}", errStr(errno));
            return -errno;
        }

        fd_ = -1;

        return 0;
    }

    private:
    int fd_ = -1;
};

int setFdNonBlock(Fd &fd)
{
    int flags = fcntl(fd.get(), F_GETFL, 0);
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
    char buffer[1024] = {};
    ::std::string data;

    while ((len = read(fd.get(), buffer, sizeof(buffer))) >= 0)
        data += ::std::string(buffer, len);

    if (len < 0 && errno != EAGAIN)
        err("failed to read from file descriptor: {}", errStr(errno));

    return data;
}

int exec(::std::string bin, ::std::vector<::std::string> args, Fd &stdoutFd,
         Fd &stderrFd)
{
    int stdout_pipe[2];
    int stderr_pipe[2];
    pid_t pid;

    // Format the argv[] array properly
    std::vector<const char *> args_;
    args_.push_back(bin.c_str());
    for (const auto &arg: args)
        args_.push_back(arg.c_str());
    args_.push_back(nullptr);

    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) {
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

        r = execvp(bin.c_str(), (char * const *)(args_.data()));

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
run(::std::string bin, ::std::vector<::std::string> args)
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
    int r = waitpid(pid, &status, 0);
    if (r < 0) {
        err("failed to wait for PID {}: {}", pid, errStr(errno));
        return {-errno, {}, {}};
    }

    auto logOut = readFd(stdoutFd);
    auto logErr = readFd(stderrFd);
    ::std::string noLog;

    return {WEXITSTATUS(status), logOut ? *logOut : noLog,
            logErr ? *logErr : noLog};
}

class Daemon
{
    public:
    class Options
    {
        public:
        Options &transient()
        {
            options_.push_back("--transient");
            return *this;
        }

        Options &noCli()
        {
            options_.push_back("--no-cli");
            return *this;
        }

        Options &noIptables()
        {
            options_.push_back("--no-iptables");
            return *this;
        }

        Options &noNftables()
        {
            options_.push_back("--no-nftables");
            return *this;
        }

        Options &bufferLen(::std::size_t len)
        {
            options_.push_back("--buffer-len");
            options_.push_back(::std::to_string(len));
            return *this;
        }

        Options &verbose(const ::std::string &component)
        {
            options_.push_back("--verbose");
            options_.push_back(component);
            return *this;
        }

        ::std::vector<::std::string> get() const
        {
            return options_;
        }

        private:
        ::std::vector<::std::string> options_;
    };

    Daemon(const ::std::string &path = "bpfilter", Options options = Options()):
        path_ {path},
        options_ {options}
    {
        if (start() < 0)
            abort("failed to start bpfilter");
    }

    Daemon(Daemon &other) = delete;

    Daemon(Daemon &&other)
    {
        if (pid_)
            abort("calling ::bf::Daemon(::bf::Daemon &&) on an active daemon!");

        other.pid_.swap(pid_);
        stdoutFd_ = ::std::move(other.stdoutFd_);
        stderrFd_ = ::std::move(other.stderrFd_);
    }

    Daemon &operator=(Daemon &other) = delete;

    Daemon &operator=(Daemon &&other)
    {
        if (pid_)
            abort(
                "calling ::bf::Daemon::operator=(::fd::Daemon &&) on an active daemon!");

        other.pid_.swap(pid_);
        stdoutFd_ = ::std::move(other.stdoutFd_);
        stderrFd_ = ::std::move(other.stderrFd_);

        return *this;
    }

    ~Daemon() noexcept(false)
    {
        if (stop() < 0)
            abort("failed to stop bpfilter");
    }

    private:
    ::std::string path_;
    Options options_;
    std::optional<pid_t> pid_;
    Fd stdoutFd_;
    Fd stderrFd_;

    int start()
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

        TimePoint begin = time::now();
        int timeout = 5;

        while (true) {
            int status;

            r = waitpid(pid, &status, WNOHANG);
            if (r == -1) {
                err("failed to wait on the deamon's PID {}: {}", pid,
                    errStr(errno));
                return -errno;
            } else if (r != 0) {
                auto errLogs = readFd(stderrFd);
                err("daemon seems to be dead! Err logs:\n{}",
                    errLogs ? *errLogs : "<no logs>");
                return -ENOENT;
            }

            auto data = readFd(stderrFd);
            if (data &&
                data->find("waiting for requests...") != ::std::string::npos)
                break;

            if (std::chrono::duration_cast<seconds>(time::now() - begin)
                    .count() > timeout) {
                // Let's try to stop it just in case
                kill(pid, SIGINT);
                err("daemon is not showing up after {} seconds, aborting",
                    timeout);
                return -EIO;
            }

            // Wait a bit for the daemon to be ready
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        pid_ = std::optional<int>(pid);
        stdoutFd_ = std::move(stdoutFd);
        stderrFd_ = std::move(stderrFd);

        return 0;
    }

    int stop()
    {
        if (!pid_)
            return 0;

        int r = kill(*pid_, SIGINT);
        if (r < 0) {
            err("failed to send SIGINT signal to the daemon: {}",
                errStr(errno));
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
};

class Program
{
    public:
    Program(std::string name):
        name_ {name}
    {
        if (open() < 0)
            abort("failed to open BPF program '{}'", name_);
    }

    Program(Program &other) = delete;

    Program(Program &&other)
    {
        if (fd_ != -1)
            abort(
                "calling ::bf::Program(::bf::Program &&) on an open program!");

        fd_ = other.fd_;
        other.fd_ = -1;
    }

    Program &operator=(Program &other) = delete;

    Program &operator=(Program &&other)
    {
        if (fd_ != -1)
            abort(
                "calling ::bf::Program::operator=(::bf::Program &&) on an open program!");

        fd_ = other.fd_;
        other.fd_ = -1;

        return *this;
    }

    ~Program() noexcept(false)
    {
        if (close() < 0)
            abort("failed to close ::bf::Program");
    }

    int run(int expect, const uint8_t *pkt, ::std::size_t pkt_len)
    {
        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = (const void *)pkt,
                    .data_size_in = (uint32_t)pkt_len, .repeat = progRunRepeat);

        int r = bpf_prog_test_run_opts(fd_, &opts);
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

    int close()
    {
        if (fd_ == -1)
            return 0;

        int r = ::close(fd_);
        if (r < 0) {
            err("failed to close ::bf::Program file descriptor: {}",
                errStr(errno));
            return -errno;
        }

        fd_ = -1;

        return 0;
    }

    private:
    ::std::string name_;
    int fd_ = -1;

    int open()
    {
        uint32_t id = 0;
        int r;

        while (true) {
            r = bpf_prog_get_next_id(id, &id);
            if (r < 0) {
                err("call to bpf_prog_get_next_id() failed: {}", errStr(r));
                return r;
            }

            int prog_fd = bpf_prog_get_fd_by_id(id);
            if (prog_fd < 0) {
                err("call to bpf_prog_get_fd_by_id() failed: {}",
                    errStr(prog_fd));
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
};

class Chain
{
    public:
    Chain(::std::string bin = "bfcli", ::std::string name = "bf_benchmark"):
        bin_ {bin},
        name_ {name}
    {}

    Chain(::std::initializer_list<::std::string> rules)
    {
        rules_.insert(rules_.begin(), rules.begin(), rules.end());
    }

    Chain &operator<<(const ::std::string &rule)
    {
        rules_.push_back(rule);
        return *this;
    }

    Chain &repeat(const ::std::string &rule, ::std::size_t count)
    {
        for (::std::size_t i = 0; i < count; ++i)
            rules_.push_back(rule);

        return *this;
    }

    int apply()
    {
        ::std::string chain = "chain BF_HOOK_CGROUP_INGRESS{cgroup=" + name_ +
                              ",name=" + name_ + ",attach=no} policy DROP ";

        for (const auto &rule: rules_)
            chain += rule + " ";

        ::std::vector<::std::string> args {"--str", chain};

        const auto [r, out, err] = run(bin_, args);
        if (r < 0) {
            err("failed to exec '{}': {}\nError logs: {}", bin_, errStr(r),
                err);
            return r;
        }

        return 0;
    }

    Program getProgram() const
    {
        Program p(name_);

        return ::std::move(p);
    }

    private:
    ::std::string bin_;
    ::std::string name_;
    ::std::vector<::std::string> rules_;
};

} // namespace bf

// Ether(
// src=0x01, dst=0x02
// )/IPv6(
// src='::1', dst='::2'
// )/TCP(
// sport=31337, dport=31415, flags='S')

#define benchLoop(state) while (state.KeepRunningBatch(::bf::progRunRepeat))

constexpr uint8_t pkt_local_ip6_tcp[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7a,
    0x69, 0x7a, 0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0x20, 0x00, 0x9a, 0xbf, 0x00, 0x0};

#define CGROUP_DROP 0
#define CGROUP_ACCEPT 1

static void firstRuleDropCounter(benchmark::State &state)
{
    ::bf::Chain chain(::bf::args.bfcli);
    chain << "rule meta.l3_proto ipv6 counter DROP";
    chain.apply();
    auto p = chain.getProgram();

    benchLoop(state)
    {
        p.run(CGROUP_DROP, static_cast<const uint8_t *>(pkt_local_ip6_tcp),
              sizeof(pkt_local_ip6_tcp));
    }
}

BENCHMARK(firstRuleDropCounter);

int main(int argc, char *argv[])
{
    struct argp argp = {::bf::options, ::bf::optsParser, nullptr, nullptr, 0,
                        nullptr,       nullptr};
    int r;

    if (geteuid() != 0) {
        err("the benchmark should be run as root");
        return -1;
    }

    r = argp_parse(&argp, argc, argv, 0, 0, &::bf::args);
    if (r < 0) {
        err("failed to parse command line arguments");
        return -1;
    }

    info("Using:");
    info("  bfcli: {}", ::bf::args.bfcli);
    info("  bpfilter: {}", ::bf::args.bpfilter);

    ::benchmark::Initialize(&argc, argv);

    auto d =
        bf::Daemon(::bf::args.bpfilter,
                   bf::Daemon::Options().transient().noIptables().noNftables());

    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
