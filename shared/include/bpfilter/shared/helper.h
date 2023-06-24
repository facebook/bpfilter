/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

extern const char *strerrordesc_np(int errnum);

#define bf_packed __attribute__((packed))

/**
 * @brief Mark a variable as unused, to prevent the compiler from emitting a
 * warning.
 *
 * @param x The variable to mark as unused.
 */
#define UNUSED(x) (void)(x)

/**
 * @brief Set @p ptr to NULL and return its previous value.
 *
 * Inspired from systemd's TAKE_PTR() macro, which is itself inspired from
 * Rust's Option::take() method:
 * https://doc.rust-lang.org/std/option/enum.Option.html#method.take
 *
 * @param var Variable to return the value of.
 * @param type Type of @p var.
 * @param nullvalue Value to set @p var to.
 * @return Value of @p var before it was set to @p nullvalue.
 */
#define TAKE_GENERIC(var, type, nullvalue)                                     \
    ({                                                                         \
        type *_pvar_ = &(var);                                                 \
        type _var_ = *_pvar_;                                                  \
        type _nullvalue_ = nullvalue;                                          \
        *_pvar_ = _nullvalue_;                                                 \
        _var_;                                                                 \
    })

#define TAKE_PTR_TYPE(ptr, type) TAKE_GENERIC(ptr, type, NULL)
#define TAKE_PTR(ptr) TAKE_PTR_TYPE(ptr, typeof(ptr))
#define TAKE_STRUCT_TYPE(s, type) TAKE_GENERIC(s, type, {})
#define TAKE_STRUCT(s) TAKE_STRUCT_TYPE(s, typeof(s))
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -1)

/**
 * @brief Get the number of element in an array.
 *
 * @param x The array.
 * @return size_t The number of elements in the array.
 */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define _cleanup_free_ __attribute__((__cleanup__(freep)))
#define _cleanup_close_ __attribute__((__cleanup__(closep)))

/**
 * @brief Return a string describing the given error code.
 *
 * This function must be used over strerror(), which is marked at mt-unsafe.
 *
 * @param v Error code, can be positive or negative.
 */
#define bf_strerror(v) strerrordesc_np(abs(v))

/**
 * @brief Free a pointer and set it to NULL.
 * @param p Pointer to free.
 */
static inline void freep(void *p)
{
    free(*(void **)p);
    *(void **)p = NULL;
}

/**
 * @brief Close a file descriptor and set it to -1.
 *
 * File descriptors are expected to be uninitialized to -1, so this function
 * can be used to close a file descriptor and set it to -1 in a single
 * operation. If the file descriptor is already -1, it is not closed.
 *
 * @param fd File descriptor to close.
 */
static inline void closep(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

/**
 * @brief Duplicate a memory region.
 *
 * Allocate a new buffer of size @p len and copy @p src into it. Requirements
 * applicable to @p src and @p len:
 * - If @p src is NULL, @p len must be 0. In this case, NULL is returned.
 * - If @p src is non-NULL, a new buffer of @p len bytes will be allocated to
 *   store the first @p len bytes of @p src. This new buffer is then returned.
 *
 * Unless NULL is returned, the new buffer is owned by the caller.
 *
 * @param src Source buffer to copy to @p dst.
 * @param len Number of bytes to copy to @p dst.
 * @return Pointer to the new buffer, or NULL on failure.
 */
static inline void *bf_memdup(const void *src, size_t len)
{
    void *dst;

    if (!src)
        return NULL;

    dst = malloc(len);
    if (!dst)
        return NULL;

    return memcpy(dst, src, len);
}

/**
 * @brief Copy @p len bytes from @p src to @p dst.
 *
 * Allow for @p src to be NULL and/or @p len to be zero:
 * - If @p src is NULL, @p len must be equal 0. @p dst is not modified.
 * - If @p src is not NULL, @p len can be equal to 0, in which case @p dst is
 *   not modified.
 *
 * @param dst Destination buffer. Can't be NULL, and must be big enough to store
 *  @p len bytes from @p src.
 * @param src Source buffer to copy to @p dst.
 * @param len Number of bytes to copy to @p dst.
 * @return Pointer to @p dst.
 */
static inline void *bf_memcpy(void *dst, const void *src, size_t len)
{
    assert(dst);
    assert(src ? 1 : len == 0);

    if (!src || !len)
        return dst;

    return memcpy(dst, src, len);
}
