/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <optional>
#include <string>

namespace bft
{

/**
 * @brief RAII wrapper for a POSIX file descriptor.
 *
 * Takes ownership of the file descriptor on construction and closes it on
 * destruction. Move-only: copy construction and copy assignment are deleted.
 * Both the move constructor and move assignment operator throw if the
 * destination already holds an open file descriptor.
 */
class FileDescriptor final
{
private:
    int fd_ = -1;

public:
    /**
     * @brief Construct a FileDescriptor, taking ownership of a raw file descriptor.
     *
     * @param fd File descriptor to own. Use -1 (the default) to create an
     *        empty Fd.
     */
    FileDescriptor(int fd = -1);

    FileDescriptor(FileDescriptor &other) = delete;
    FileDescriptor &operator=(FileDescriptor &other) = delete;

    /**
     * @brief Move-construct.
     *
     * @throw std::runtime_error If the assigned-to object already holds an open file descriptor.
     */
    FileDescriptor(FileDescriptor &&other) noexcept(false);

    /**
     * @brief Move-assign.
     *
     * @throw std::runtime_error If the assigned-to object already holds an open file descriptor.
     * @return FileDescriptor object.
     */
    FileDescriptor &operator=(FileDescriptor &&other) noexcept(false);

    ~FileDescriptor();

    /**
     * @brief Return the raw file descriptor value, or -1 if empty.
     *
     * The file descriptor returned should not be closed as it's still
     * owned by the object.
     *
     * @return The file descriptor.
     */
    [[nodiscard]] int get() const;

    /**
     * @brief Release ownership and return the raw file descriptor.
     *
     * After this call the object is empty (-1) and the caller is
     * responsible for closing the returned file descriptor.
     *
     * @return The raw file descriptor, or -1 if already empty.
     */
    [[nodiscard]] int release();

    /**
     * @brief Set `O_NONBLOCK` flag on the file descriptor.
     *
     * @return 0 on success, or a negative errno value on failure.
     */
    [[nodiscard]] int setNonBlock() const;
};

std::optional<std::string> read(FileDescriptor &fd);

} // namespace bft
