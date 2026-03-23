/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "benchmark.hpp"

#include <linux/bpf.h>

#include <argp.h>
#include <array>
#include <benchmark/benchmark.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <git2/commit.h>
#include <git2/errors.h>
#include <git2/global.h>
#include <git2/oid.h>
#include <git2/refs.h>
#include <git2/repository.h>
#include <git2/status.h>
#include <git2/types.h>
#include <iostream> // NOLINT
#include <span>
#include <sstream>
#include <string>
#include <sys/personality.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

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

namespace bft
{

constexpr int CGROUP_SKB_DROP = 0;
constexpr int CGROUP_SKB_ACCEPT = 1;

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

constexpr std::array<uint8_t, 42> pkt_local_ip4_icmp {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
    0x40, 0x01, 0x68, 0xc7, 0x7f, 0x02, 0x0a, 0x0a, 0x7f, 0x02, 0x0a,
    0x0b, 0x08, 0x02, 0xf7, 0xfd, 0x00, 0x00, 0x00, 0x00};
constexpr std::array<uint8_t, 54> pkt_local_ip4_tcp {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
    0x40, 0x06, 0x68, 0xb6, 0x7f, 0x02, 0x0a, 0x0a, 0x7f, 0x02, 0x0a,
    0x0b, 0x00, 0x17, 0x00, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x7d, 0x41, 0x00, 0x00};
constexpr std::array<uint8_t, 90> pkt_remote_ip6_eh {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x40, 0x54, 0x2c,
    0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c, 0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26,
    0xb8, 0x7e, 0x52, 0x32, 0x18, 0x5a, 0x52, 0xf9, 0x0a, 0xb4, 0x80, 0x25,
    0x79, 0x74, 0x22, 0x99, 0xeb, 0x04, 0x2b, 0x00, 0x01, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x00,
    0x01, 0x04, 0x00, 0x00, 0x00, 0x00};
constexpr int progRunRepeat = 1000000;

Config config = {};

namespace
{
constexpr int maxCommitHashLen = 7;

enum
{
    OPT_KEY_ADHOC,
    OPT_KEY_ADHOC_REPEAT,
};

const ::std::string help = "\v\
--adhoc option is used to run an adhoc benchmark. When used, pre-defined \
benchmarks will be skipped, and only the adhoc benchmark will be run. --adhoc \
benchmarks won't create any output file.";

constexpr std::array<struct argp_option, 8> options {{
    {
        .name = "cli",
        .key = 'c',
        .arg = "CLI",
        .flags = 0,
        .doc = "Path to the bfcli binary. Defaults to 'bfcli' in $PATH.",
        .group = 0,
    },
    {
        .name = "srcdir",
        .key = 's',
        .arg = "SOURCES_DIR",
        .flags = 0,
        .doc =
            "Path to the bpfilter sources folder used to build bpfilter. Defaults to the current directory.",
        .group = 0,
    },
    {
        .name = "outfile",
        .key = 'o',
        .arg = "OUTPUT_FILE",
        .flags = 0,
        .doc =
            "Path to the JSON file to write the results to. Defaults to 'results.json'.",
        .group = 0,
    },
    {
        .name = "filter",
        .key = 'f',
        .arg = "FILTER",
        .flags = 0,
        .doc =
            "Only run benchmarks matching the given FILTER (substring match).",
        .group = 0,
    },
    {
        .name = "list",
        .key = 'l',
        .arg = nullptr,
        .doc = "List all available benchmarks and exit.",
        .group = 0,
    },
    {.name = nullptr},
}};

int optsParser(int key, char *arg, struct ::argp_state *state)
{
    auto *config = static_cast<Config *>(state->input);

    switch (key) {
    case 'c':
        config->bfcli = ::std::filesystem::absolute(arg);
        break;
    case 's':
        config->srcdir = ::std::string(arg);
        break;
    case 'o':
        config->outfile = ::std::string(arg);
        break;
    case 'f':
        ::benchmark::SetBenchmarkFilter(::std::string(arg));
        break;
    case 'l':
        ::benchmark::FLAGS_benchmark_list_tests = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

} // namespace

int disableASLR(char **argv)
{
    // Inspired by Google Benchmark:
    // https://github.com/google/benchmark/blob/eddb024/src/benchmark.cc#L826-L861

    // Disable ASLR for the current process
    unsigned long curr_personality = personality(0xffffffff);
    if (curr_personality == -1)
        return bf_err_r(errno, "failed to read current process personality");

    // Is ASLR is already disabled, return and proceed to the benchmark
    if (curr_personality & ADDR_NO_RANDOMIZE)
        return 0;

    unsigned long new_personality =
        personality(curr_personality | ADDR_NO_RANDOMIZE);
    if (new_personality == -1)
        return bf_err_r(errno, "failed to set new process personality");

    execv(argv[0], argv);

    return 0;
}

static std::string which(const std::string &cmd)
{
    // If already a path, resolve directly
    if (cmd.find('/') != std::string::npos) {
        auto p = std::filesystem::absolute(cmd);
        if (std::filesystem::exists(p))
            return p.string();
        return {};
    }

    const char *path_env = std::getenv("PATH");
    if (path_env == nullptr)
        return {};

    std::istringstream ss(path_env);
    std::string dir;

    while (std::getline(ss, dir, ':')) {
        auto candidate = std::filesystem::path(dir) / cmd;
        if (std::filesystem::exists(candidate) &&
            access(candidate.c_str(), X_OK) == 0) {
            return std::filesystem::absolute(candidate).string();
        }
    }
    return {};
}

int setup(std::span<char *> args)
{
    const struct argp argp = {.options = options.data(),
                              .parser = optsParser,
                              .args_doc = nullptr,
                              .doc = help.c_str()};

    const int r = argp_parse(&argp, static_cast<int>(args.size()), args.data(),
                             0, nullptr, &::bft::config);
    if (r != 0)
        return bf_err_r(r, "failed to parse command line arguments");

    config.bfcli = which(config.bfcli);
    if (config.bfcli.empty()) {
        return bf_err_r(-ENOENT, "bfcli binary '%s' not found",
                        config.bfcli.c_str());
    }

    config.outfile = ::std::filesystem::absolute(config.outfile);
    config.srcdir = ::std::filesystem::weakly_canonical(config.srcdir);
    if (!std::filesystem::exists(config.srcdir)) {
        return bf_err_r(-ENOENT, "source directory '%s' does not exist",
                        config.srcdir.c_str());
    }

    const ::bft::Sources srcs(::bft::config.srcdir);

    if (srcs.isDirty()) {
        config.gitrev = srcs.getLastCommitHash() + "+";
        config.gitdate =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
    } else {
        config.gitrev = srcs.getLastCommitHash();
        config.gitdate = srcs.getLastCommitTime();
    }

    const ::std::string pattern = "{gitrev}";
    const auto pos = config.outfile.find(pattern);
    if (pos != ::std::string::npos)
        config.outfile.replace(pos, pattern.size(), config.gitrev);

    ::benchmark::AddCustomContext("gitrev", config.gitrev);
    ::benchmark::AddCustomContext("gitdate", ::std::to_string(config.gitdate));
    ::benchmark::AddCustomContext("bfcli", config.bfcli);
    ::benchmark::AddCustomContext("srcdir", config.srcdir);
    ::benchmark::AddCustomContext("outfile", config.outfile);
    ::benchmark::FLAGS_benchmark_out = config.outfile;
    ::benchmark::FLAGS_benchmark_out_format = "json";

    return 0;
}

void restorePermissions(::std::string outfile)
{
    const char *uid = getenv("SUDO_UID");
    const char *gid = getenv("SUDO_GID");

    if (uid && gid) {
        int r = chown(outfile.c_str(), atoi(uid), atoi(gid));
        if (r) {
            ::std::cerr
                << "failed to restore output file permissions to SUDO_USER\n";
            return;
        }
        ::std::cout << "sudo is used, output file permissions restored to "
                    << uid << ":" << gid << "\n";
    }
}

Sources::Sources(::std::string path):
    path_ {::std::move(path)}
{
    int r = git_libgit2_init();
    if (r < 0) {
        const git_error *git_err = git_error_last();
        throw std::runtime_error(
            std::format("failed to initialize libgit2: {}/{}: {}", r,
                        git_err->klass, git_err->message));
    }

    r = git_repository_open(&repo_, path_.c_str());
    if (r < 0) {
        const git_error *git_err = git_error_last();
        throw std::runtime_error(
            std::format("failed to open Git repository: {}/{}: {}", r,
                        git_err->klass, git_err->message));
    }
}

Sources::~Sources()
{
    git_repository_free(repo_);
    git_libgit2_shutdown();
}

::std::string Sources::getLastCommitHash() const
{
    git_oid oid;
    ::std::array<char, GIT_OID_SHA1_HEXSIZE + 1> buff;

    int r = git_reference_name_to_id(&oid, repo_, "HEAD");
    if (r < 0) {
        const git_error *git_err = git_error_last();
        bf_err("failed to resolve HEAD: %d/%d: %s", r, git_err->klass,
               git_err->message);
        return "";
    }

    return {git_oid_tostr(buff.data(), buff.size(), &oid), maxCommitHashLen};
}

int64_t Sources::getLastCommitTime() const
{
    git_oid oid;
    git_commit *commit;

    int r = git_reference_name_to_id(&oid, repo_, "HEAD");
    if (r < 0) {
        const git_error *git_err = git_error_last();
        bf_err("failed to convert Git reference to ID: %d/%d: %s", r,
               git_err->klass, git_err->message);
        return -1;
    }

    r = git_commit_lookup(&commit, repo_, &oid);
    if (r < 0) {
        const git_error *git_err = git_error_last();
        bf_err("failed to get git commit: %d/%d: %s", r, git_err->klass,
               git_err->message);
        return -1;
    }

    auto time = git_commit_time(commit);
    git_commit_free(commit);

    return time;
}

bool Sources::isDirty() const
{
    git_status_list *status;
    const git_status_options opts = {
        .version = GIT_STATUS_OPTIONS_VERSION,
    };

    int r = git_status_list_new(&status, repo_, &opts);
    if (r < 0) {
        const git_error *git_err = git_error_last();
        bf_err("failed to get repository status: %d/%d: %s", r, git_err->klass,
               git_err->message);
        return true;
    }

    auto count = git_status_list_entrycount(status);
    git_status_list_free(status);

    return count != 0;
}

} // namespace bft
