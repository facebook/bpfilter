/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <optional>
#include <string>
#include <sys/types.h>
#include <tuple>
#include <vector>

#include "FileDescriptor.hpp"

namespace bft
{

/**
 * @brief Manages the lifecycle of a bpfilter daemon process.
 *
 * Spawns the daemon as a child process on construction, capturing its stdout
 * and stderr through pipes. Waits up to 5 seconds for the daemon to signal
 * readiness by printing "waiting for requests..." on stderr. Sends SIGINT
 * and waits for the process to exit on destruction.
 *
 * Move-only: copy construction and copy assignment are deleted. Both the move
 * constructor and move assignment operator throw if the destination already
 * manages an active daemon.
 */
class Daemon final
{
public:
    /**
     * @brief Builder for bpfilter daemon command-line options.
     *
     * Each method appends the corresponding flag(s) to the option list and
     * returns `*this` to allow chaining.
     */
    class Options
    {
    public:
        /**
         * @brief Append `--transient` to the option list.
         *
         * @return Reference to this Options object for chaining.
         */
        Options &transient();

        /**
         * @brief Append `--verbose <component>` to the option list.
         *
         * @param component Logging component name to enable verbose output for.
         * @return Reference to this Options object for chaining.
         */
        Options &verbose(const std::string &component);

        /**
         * @brief Return the assembled option strings.
         *
         * @return Vector of option strings.
         */
        [[nodiscard]] std::vector<std::string> get() const;

    private:
        std::vector<std::string> options_;
    };

    /**
     * @brief Start a bpfilter daemon process.
     *
     * Forks and execs the binary at `path` with the given `options`. Throws
     * if the daemon fails to start or does not become ready within the timeout.
     *
     * @param path Path to the bpfilter binary (default: "bpfilter").
     * @param options Command-line options forwarded to the daemon.
     * @throw std::runtime_error If the daemon fails to start or become ready.
     */
    Daemon(std::string path = "bpfilter", Options options = Options());

    Daemon(const Daemon &) = delete;
    Daemon &operator=(const Daemon &) = delete;

    /**
     * @brief Move-construct.
     *
     * @throw std::runtime_error If this object already manages an active daemon.
     */
    Daemon(Daemon &&other) noexcept(false);

    /**
     * @brief Move-assign.
     *
     * @throw std::runtime_error If this object already manages an active daemon.
     */
    Daemon &operator=(Daemon &&other) noexcept(false);

    /**
     * @brief Stop the daemon.
     */
    ~Daemon();

    /**
     * @brief Drain and return all output the daemon has written to stdout.
     *
     * @return Accumulated stdout output since the last call.
     */
    std::string stdout();

    /**
     * @brief Drain and return all output the daemon has written to stderr.
     *
     * @return Accumulated stderr output since the last call.
     */
    std::string stderr();

private:
    std::string path_;
    Options options_;
    std::optional<pid_t> pid_;
    FileDescriptor stdoutFd_;
    FileDescriptor stderrFd_;
};

/**
 * @brief Fork and exec a binary, returning pipe handles for its output.
 *
 * The child's stdout and stderr are redirected to pipes whose read ends
 * are returned in `out` and `err`. The caller is responsible for waiting
 * on the returned PID.
 *
 * @param bin Path to the binary to execute.
 * @param args Command-line arguments to pass to the binary.
 * @param out On success, receives the read end of the child's stdout pipe.
 * @param err On success, receives the read end of the child's stderr pipe.
 * @return Child PID on success, or a negative errno value on failure.
 */
int exec(const std::string &bin, const std::vector<std::string> &args,
         FileDescriptor &out, FileDescriptor &err);

/**
 * @brief Fork and exec a binary, wait for it to finish, and capture its output.
 *
 * @param bin Path to the binary to execute.
 * @param args Command-line arguments to pass to the binary.
 * @return Tuple of (exit status, stdout output, stderr output).
 */
std::tuple<int, std::string, std::string>
run(const std::string &bin, const std::vector<std::string> &args);

} // namespace bft
