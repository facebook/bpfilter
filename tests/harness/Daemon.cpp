/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "Daemon.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

#include "FileDescriptor.hpp"

extern "C" {
// clang-format off
#include <stdarg.h> // NOLINT: required by cmocka.h
#include <stddef.h> // NOLINT: required by cmocka.h
#include <stdint.h> // NOLINT: required by cmocka.h
#include <setjmp.h> // NOLINT: required by cmocka.h
#include <cmocka.h> // NOLINT: required by cmocka.h
// clang-format on

#include <bpfilter/logger.h>
}

using bft::Daemon;
using bft::FileDescriptor;

namespace
{
constexpr int waitForDaemonTimeoutS = 5;
constexpr int waitForDaemonSleepMs = 10;

using TimePoint = std::chrono::steady_clock::time_point;
using time = std::chrono::steady_clock;
using seconds = std::chrono::seconds;
} // namespace

int bft::exec(const std::string &bin, const std::vector<std::string> &args,
              FileDescriptor &out, FileDescriptor &err)
{
    pid_t pid;

    // Format the argv[] array properly
    std::vector<const char *> args_;
    args_.push_back(bin.c_str());
    for (const auto &arg: args)
        args_.push_back(arg.c_str());
    args_.push_back(nullptr);

    std::array<int, 2> stdout_pipe;
    if (pipe(stdout_pipe.data()) < 0) {
        return bf_err_r(errno, "failed to create stdout pipe for '%s'",
                        bin.c_str());
    }
    FileDescriptor stdout_r(stdout_pipe[0]), stdout_w(stdout_pipe[1]);

    std::array<int, 2> stderr_pipe;
    if (pipe(stderr_pipe.data()) < 0) {
        return bf_err_r(errno, "failed to create stderr pipe for '%s'",
                        bin.c_str());
    }
    FileDescriptor stderr_r(stderr_pipe[0]), stderr_w(stderr_pipe[1]);

    pid = fork();
    if (pid < 0)
        return bf_err_r(errno, "failed to fork '%s'", bin.c_str());

    /* Child path: use raw close() and _exit() only. RAII destructors don't
     * run because _exit() / execvp() bypass stack unwinding. */
    if (pid == 0) {
        int r;

        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        r = dup2(stdout_pipe[1], STDOUT_FILENO);
        if (r < 0)
            _exit(errno);

        r = dup2(stderr_pipe[1], STDERR_FILENO);
        if (r < 0)
            _exit(errno);

        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        (void)execvp(bin.c_str(), const_cast<char * const *>(args_.data()));

        // If execvp returns, an error occurred
        _exit(errno);
    }

    // Send back the read-end pipes FD and PID to the parent
    out = std::move(stdout_r);
    err = std::move(stderr_r);

    return pid;
}

std::tuple<int, std::string, std::string>
bft::run(const std::string &bin, const std::vector<std::string> &args)
{
    FileDescriptor out, err;

    int pid = bft::exec(bin, args, out, err);
    if (pid < 0) {
        bf_err("failed to exec '%s': %s", bin.c_str(), strerror(abs(pid)));
        return {pid, {}, {}};
    }

    if (out.setNonBlock() < 0 || err.setNonBlock() < 0) {
        bf_err("failed to set FD non-blocking for '%s': %s", bin.c_str(),
               strerror(errno));
        return {-errno, {}, {}};
    }

    int status;
    const int r = waitpid(pid, &status, 0);
    if (r < 0) {
        bf_err("failed to wait for PID %d: %s", pid, strerror(errno));
        return {-errno, {}, {}};
    }

    const auto logOut = bft::read(out);
    const auto logErr = bft::read(err);

    return {WEXITSTATUS(status), logOut ? *logOut : "", logErr ? *logErr : ""};
}

Daemon::Options &Daemon::Options::transient()
{
    options_.emplace_back("--transient");
    return *this;
}

Daemon::Options &Daemon::Options::verbose(const std::string &component)
{
    options_.emplace_back("--verbose");
    options_.emplace_back(component);
    return *this;
}

std::vector<std::string> Daemon::Options::get() const
{
    return options_;
}

Daemon::Daemon(std::string path, Options options):
    path_ {std::move(path)},
    options_ {std::move(options)}
{
    FileDescriptor out, err;
    pid_t pid;
    int r;

    pid = exec(path_, options_.get(), out, err);
    if (pid < 0)
        throw std::runtime_error("failed to start the daemon");

    if ((r = out.setNonBlock()) < 0) {
        kill(pid, SIGINT);
        waitpid(pid, nullptr, 0);
        throw std::runtime_error(
            "failed to set non-blocking flag to the daemon's stdout FD");
    }

    if ((r = err.setNonBlock()) < 0) {
        kill(pid, SIGINT);
        waitpid(pid, nullptr, 0);
        throw std::runtime_error(
            "failed to set non-blocking flag to the daemon's stderr FD");
    }

    const TimePoint begin = time::now();
    while (true) {
        int status;

        r = waitpid(pid, &status, WNOHANG);
        if (r == -1) {
            kill(pid, SIGINT);
            waitpid(pid, nullptr, 0);
            throw std::runtime_error(
                std::format("failed to wait on the daemon's PID {}", pid));
        }
        if (r != 0) {
            auto logs = bft::read(err);
            throw std::runtime_error(std::format(
                "daemon exited prematurely: {}", logs ? *logs : "<no logs>"));
        }

        auto data = bft::read(err);
        if (data && data->find("waiting for requests...") != std::string::npos)
            break;

        if (std::chrono::duration_cast<seconds>(time::now() - begin).count() >
            waitForDaemonTimeoutS) {
            kill(pid, SIGINT);
            waitpid(pid, nullptr, 0);
            throw std::runtime_error(std::format(
                "daemon not ready after {} seconds", waitForDaemonTimeoutS));
        }

        std::this_thread::sleep_for(
            std::chrono::milliseconds(waitForDaemonSleepMs));
    }

    pid_ = std::optional<int>(pid);
    stdoutFd_ = std::move(out);
    stderrFd_ = std::move(err);
}

Daemon::Daemon(Daemon &&other) noexcept(false)
{
    if (pid_) {
        throw std::runtime_error(
            "calling ::bft::Daemon(::bft::Daemon &&) on an active daemon!");
    }

    other.pid_.swap(pid_);
    stdoutFd_ = std::move(other.stdoutFd_);
    stderrFd_ = std::move(other.stderrFd_);
}

Daemon &Daemon::operator=(Daemon &&other) noexcept(false)
{
    if (pid_) {
        throw std::runtime_error(
            "calling ::bft::Daemon::operator=(::bft::Daemon &&) on an active daemon!");
    }

    other.pid_.swap(pid_);
    stdoutFd_ = std::move(other.stdoutFd_);
    stderrFd_ = std::move(other.stderrFd_);

    return *this;
}

Daemon::~Daemon()
{
    if (!pid_)
        return;

    kill(*pid_, SIGINT);
    waitpid(*pid_, nullptr, 0);
}

std::string Daemon::stdout()
{
    auto maybe = bft::read(stdoutFd_);

    return maybe ? *maybe : "";
}

std::string Daemon::stderr()
{
    auto maybe = bft::read(stderrFd_);

    return maybe ? *maybe : "";
}
