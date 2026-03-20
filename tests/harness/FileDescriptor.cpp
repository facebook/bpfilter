/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "FileDescriptor.hpp"

#include <array>
#include <optional>
#include <stdexcept>

extern "C" {
#include <fcntl.h>
#include <unistd.h>

#include <bpfilter/logger.h>
}

using bft::FileDescriptor;

FileDescriptor::FileDescriptor(int fd):
    fd_ {fd}
{}

FileDescriptor::FileDescriptor(FileDescriptor &&other) noexcept(false)
{
    if (fd_ != -1) {
        throw std::runtime_error(
            "calling ::bft::FileDescriptor(FileDescriptor &&) on an open file descriptor!");
    }

    fd_ = other.fd_;
    other.fd_ = -1;
}

FileDescriptor &
FileDescriptor::operator=(FileDescriptor &&other) noexcept(false)
{
    if (fd_ != -1) {
        throw std::runtime_error(
            "calling ::bft::FileDescriptor::operator=(FileDescriptor &&) on an open file descriptor!");
    }

    fd_ = other.fd_;
    other.fd_ = -1;

    return *this;
}

FileDescriptor::~FileDescriptor()
{
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

int FileDescriptor::get() const
{
    return fd_;
}

int FileDescriptor::release()
{
    int fd = fd_;
    fd_ = -1;
    return fd;
}

int FileDescriptor::setNonBlock() const
{
    if (fd_ < 0)
        return -ENOENT;

    const int flags = ::fcntl(fd_, F_GETFL, 0);
    if (flags < 0)
        return bf_err_r(errno, "failed to get current flags for FD %d", fd_);

    if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0)
        return bf_err_r(errno, "failed to set non-block flag on FD %d", fd_);

    return 0;
}

std::optional<std::string> bft::read(FileDescriptor &fd)
{
    ssize_t len;
    std::array<char, 1024> buffer;
    std::string data;

    while ((len = ::read(fd.get(), buffer.data(), buffer.size())) > 0)
        data.append(buffer.data(), len);

    if (len < 0 && errno != EAGAIN) {
        bf_err_r(errno, "failed to read from file descriptor");
        return std::nullopt;
    }

    return data;
}
