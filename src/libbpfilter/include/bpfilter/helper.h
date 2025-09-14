/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

extern const char *strerrordesc_np(int errnum);

#define _BF_APPLY0(t, s, dummy)
#define _BF_APPLY1(t, s, a) t(a)
#define _BF_APPLY2(t, s, a, b) t(a) s t(b)
#define _BF_APPLY3(t, s, a, b, c)                                              \
    t(a) s t(b)                                                                \
    s t(c)
#define _BF_APPLY4(t, s, a, b, c, d)                                           \
    t(a) s t(b)                                                                \
    s t(c)                                                                     \
    s t(d)
#define _BF_APPLY5(t, s, a, b, c, d, e)                                        \
    t(a) s t(b)                                                                \
    s t(c)                                                                     \
    s t(d)                                                                     \
    s t(e)
#define _BF_APPLY6(t, s, a, b, c, d, e, f)                                     \
    t(a) s t(b)                                                                \
    s t(c)                                                                     \
    s t(d)                                                                     \
    s t(e)                                                                     \
    s t(f)
#define _BF_APPLY7(t, s, a, b, c, d, e, f, g)                                  \
    t(a) s t(b)                                                                \
    s t(c)                                                                     \
    s t(d)                                                                     \
    s t(e)                                                                     \
    s t(f)                                                                     \
    s t(g)
#define _BF_APPLY8(t, s, a, b, c, d, e, f, g, h)                               \
    t(a) s t(b)                                                                \
    s t(c)                                                                     \
    s t(d)                                                                     \
    s t(e)                                                                     \
    s t(f)                                                                     \
    s t(g)                                                                     \
    s t(h)
#define _BF_APPLY9(t, s, a, b, c, d, e, f, g, h, i)                            \
    t(a) s t(b)                                                                \
    s t(c)                                                                     \
    s t(d)                                                                     \
    s t(e)                                                                     \
    s t(f)                                                                     \
    s t(g)                                                                     \
    s t(h)                                                                     \
    s t(i)
#define _BF_APPLY10(t, s, a, b, c, d, e, f, g, h, i, j)                        \
    t(a) s t(b)                                                                \
    s t(c)                                                                     \
    s t(d)                                                                     \
    s t(e)                                                                     \
    s t(f)                                                                     \
    s t(g)                                                                     \
    s t(h)                                                                     \
    s t(i)                                                                     \
    s t(j)

#define __BF_NUM_ARGS1(dummy, x10, x9, x8, x7, x6, x5, x4, x3, x2, x1, x0,     \
                       ...)                                                    \
    x0
#define _BF_NUM_ARGS(...)                                                      \
    __BF_NUM_ARGS1(dummy, ##__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define ___BF_APPLY_ALL(t, s, n, ...) _BF_APPLY##n(t, s, __VA_ARGS__)
#define __BF_APPLY_ALL(t, s, n, ...) ___BF_APPLY_ALL(t, s, n, __VA_ARGS__)
#define _BF_APPLY_ALL(t, s, ...)                                               \
    __BF_APPLY_ALL(t, s, _BF_NUM_ARGS(__VA_ARGS__), __VA_ARGS__)

#define BF_BASE_10 10
#define BF_BASE_16 16

#define _BF_ALIGNED(addr, mask) (((addr) & (mask)) == 0)
#define BF_ALIGNED_64(addr) _BF_ALIGNED(addr, 0x07)
#define BF_ALIGNED_32(addr) _BF_ALIGNED(addr, 0x03)
#define BF_ALIGNED_16(addr) _BF_ALIGNED(addr, 0x01)

/**
 * @brief Generate a bitflag from multiple values.
 *
 * Enumeration are used extensively to define related values. Thanks to
 * enumeration's continuous values, they are used as array indexes to convert
 * them into strings.
 *
 * However, they can sometimes be combined, leading to very wordy code, e.g.
 * `1 << ENUM_VAL_1 | 1 << ENUM_VAL_5`.
 *
 * `BF_FLAGS` can be used to replace the wordy code with a simpler macro call,
 * e.g. `BF_FLAGS(ENUL_VAL_1, ENUM_VAL_5)`. It will automatically create an
 * integer with the enumeration values as a set bit index in the bitflag.
 *
 * @return Bitflag for variadic values.
 */
#define BF_FLAGS(...) _BF_APPLY_ALL(BF_FLAG, |, __VA_ARGS__)

/**
 * @brief Shift 1 by `n` to create a flag.
 *
 * @see `BF_FLAGS`
 *
 * @return `1 << n` to be used as a flag.
 */
#define BF_FLAG(n) (1 << (n))

#define bf_packed __attribute__((packed))
#define bf_aligned(x) __attribute__((aligned(x)))
#define bf_unused __attribute__((unused))

#ifndef bf_assert
#define bf_assert(x) assert(x)
#endif

#define bf_static_assert(expr, msg) _Static_assert((expr), msg)

#define BF_STR(s) _BF_STR(s)
#define _BF_STR(s) #s

/**
 * @brief Generate a build error if an enumeration to string mapping array
 *        contains fewer entries than members in the enumeration.
 *
 * @param array Array containing the mapping between the enumeration values and
 *        ther string representation.
 * @param n_values Number of values in the enumeration, usually the
 *        `_BF_$NAME_MAX` enumeration value.
 */
#define static_assert_enum_mapping(array, n_values)                            \
    static_assert(ARRAY_SIZE(array) == (n_values),                             \
                  "missing entries in " BF_STR(array) " array");

/**
 * Mark a variable as unused, to prevent the compiler from emitting a warning.
 *
 * @param x The variable to mark as unused.
 */
#define UNUSED(x) (void)(x)

/**
 * Set @p ptr to NULL and return its previous value.
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
        /* NOLINTBEGIN: do not enclose 'type' in parentheses */                \
        type *_pvar_ = &(var);                                                 \
        type _var_ = *_pvar_;                                                  \
        type _nullvalue_ = nullvalue;                                          \
        /* NOLINTEND */                                                        \
        *_pvar_ = _nullvalue_;                                                 \
        _var_;                                                                 \
    })

#define TAKE_PTR_TYPE(ptr, type) TAKE_GENERIC(ptr, type, NULL)
#define TAKE_PTR(ptr) TAKE_PTR_TYPE(ptr, typeof(ptr))
#define TAKE_STRUCT_TYPE(s, type) TAKE_GENERIC(s, type, {})
#define TAKE_STRUCT(s) TAKE_STRUCT_TYPE(s, typeof(s))
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -1)

/**
 * Get the number of element in an array.
 *
 * @param x The array.
 * @return size_t The number of elements in the array.
 */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define _cleanup_free_ __attribute__((__cleanup__(freep)))
#define _cleanup_close_ __attribute__((__cleanup__(closep)))

/**
 * Return a string describing the given error code.
 *
 * This function must be used over strerror(), which is marked at mt-unsafe.
 *
 * @param v Error code, can be positive or negative.
 */
#define bf_strerror(v) strerrordesc_np(abs(v))

/**
 * Swap two values.
 *
 * @param a First value to swap.
 * @param b Second value to swap.
 */
#define bf_swap(a, b)                                                          \
    do {                                                                       \
        typeof(a) __a = (a);                                                   \
        (a) = (b);                                                             \
        (b) = __a;                                                             \
    } while (0)

#define bf_min(a, b)                                                           \
    ({                                                                         \
        __typeof__(a) _a = (a);                                                \
        __typeof__(b) _b = (b);                                                \
        _a < _b ? _a : _b;                                                     \
    })

#define bf_max(a, b)                                                           \
    ({                                                                         \
        __typeof__(a) _a = (a);                                                \
        __typeof__(b) _b = (b);                                                \
        _a > _b ? _a : _b;                                                     \
    })

/**
 * @brief Strip whitespace from the beginning of a string.
 *
 * @param str String to trim. Can't be NULL.
 * @return Trimmed version of `str`, as a pointer to a character of `str`.
 */
char *bf_ltrim(char *str);

/**
 * @brief Strip whitespace from the end of a string.
 *
 * `str` will be modified to insert `\0` after the last non-whitespace
 * character.
 * @param str String to trim. Can't be NULL.
 * @return Trimmed version of `str`, as a pointer to a character of `str`.
 */
char *bf_rtrim(char *str);

/**
 * @brief Strip whitespace from the beginning and the end of a string.
 *
 * `str` will be modified to insert `\0` after the last non-whitespace
 * character.
 *
 * @param str String to trim. Can't be NULL.
 * @return Trimmed version of `str`, as a pointer to a character of `str`.
 */
char *bf_trim(char *str);

/**
 * Free a pointer and set it to NULL.
 *
 * @param ptr Pointer to free.
 */
static inline void freep(void *ptr)
{
    free(*(void **)ptr);
    *(void **)ptr = NULL;
}

/**
 * Close a file descriptor and set it to -1.
 *
 * `bpfilter` uses `-1` as neutral value for file descriptor, meaning it
 * doesn't represent an open file yet. Once closed, a file descriptor should
 * be reset to `-1`.
 *
 * `closep` is used to close a file descriptor. If the file descriptor is
 * `-1`, then nothing it done. Otherwise, it is closed and reset to `-1`.
 *
 * If the call to `close` fails, a warning is printed, and the file descriptor
 * is assumed to be already closed.
 *
 * @todo Ensure file descriptors are always initialized to -1, and closed using
 * ``closep``.
 *
 * @param fd File descriptor to close. Can't be NULL.
 */
void closep(int *fd);

/**
 * Duplicate a memory region.
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
 * Copy @p len bytes from @p src to @p dst.
 *
 * Allow for @p src to be NULL and/or @p len to be zero:
 * - If @p src is NULL, @p len must be equal 0. @p dst is not modified.
 * - If @p src is not NULL, @p len can be equal to 0, in which case @p dst is
 *   not modified.
 *
 * @param dst Destination buffer. Can't be NULL, and must be big enough to store
 *        @p len bytes from @p src.
 * @param src Source buffer to copy to @p dst.
 * @param len Number of bytes to copy to @p dst.
 * @return Pointer to @p dst.
 */
static inline void *bf_memcpy(void *dst, const void *src, size_t len)
{
    bf_assert(dst);
    bf_assert(src ? 1 : len == 0);

    if (!src || !len)
        return dst;

    return memcpy(dst, src, len);
}

/**
 * Reallocate @p ptr into a new buffer of size @p size.
 *
 * Behaves similarly to realloc(), except that @p ptr is left unchanged if
 * allocation fails, and an error is returned.
 *
 * @param ptr Memory buffer to grow. Can't be NULL.
 * @param size New size of the memory buffer.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_realloc(void **ptr, size_t size);

/**
 * @brief Check if strings are equal.
 *
 * If any of `lhs`, `rhs` is NULL, the strings are considered inequal.
 *
 * @param lhs First string.
 * @param rhs Second string.
 * @return True if both strings are equal.
 */
static inline bool bf_streq(const char *lhs, const char *rhs)
{
    if (!lhs || !rhs)
        return false;

    return strcmp(lhs, rhs) == 0;
}

/**
 * @brief Similar to `bf_streq`, except it compares only the first `n`
 * characters.
 *
 * If any of `lhs`, `rhs` is NULL, the strings are considered inequal.
 *
 * @param lhs First string.
 * @param rhs Second string.
 * @param n Number of characters to compare.
 * @return True if both strings are equal.
 */
static inline bool bf_strneq(const char *lhs, const char *rhs, size_t n)
{
    if (!lhs || !rhs)
        return false;

    return strncmp(lhs, rhs, n);
}

/**
 * @brief Case insensitive alternative to `bf_streq`.
 */
static inline bool bf_streq_i(const char *lhs, const char *rhs)
{
    if (!lhs || !rhs)
        return false;

    return strcasecmp(lhs, rhs) == 0;
}

/**
 * Copy a string to a buffer.
 *
 * @p src is copied to @p dst . If @p src is too long, at most @p len bytes are
 * copied (including the termination character).
 *
 * @param dst Destination buffer. Can't be NULL.
 * @param len Length of the destination buffer. The function will not copy more
 *        than @p len bytes to @p dst , including @c \0 . Can't be 0.
 * @param src Soucre buffer to copy from. Will only be copied up to the
 *        termination character if it fits. Can't be NULL.
 * @return 0 on success, or @c -E2BIG if @p src can't fit in @p dst .
 */
int bf_strncpy(char *dst, size_t len, const char *src);

/**
 * Read the contents of a file into a buffer.
 *
 * @param path Path to the file to read. Can't be NULL.
 * @param buf Pointer to a pointer to a buffer. The buffer will be allocated
 *        automatically. The caller is responsible to free it. If @ref
 * bf_read_file fails, @p buf is left unchanged.
 * @param len Length of the allocated buffer. Populated by the function.
 * @return 0 on success, negative errno value on error.
 */
int bf_read_file(const char *path, void **buf, size_t *len);

/**
 * Write the contents of a buffer into a file.
 *
 * @param path Path to the file to write. Can't be NULL.
 * @param buf Buffer to write.
 * @param len Number of bytes to write the to file.
 * @return 0 on success, negative errno value on error.
 */
int bf_write_file(const char *path, const void *buf, size_t len);
