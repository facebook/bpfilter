/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "core/lock.h"

#include <linux/limits.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpfilter/ctx.h>

#include "test.h"

/* ------------------------------------------------------------------
 * bf_lock_default()
 * ------------------------------------------------------------------ */

/* Post-condition of bf_lock_default(): all fds == -1, all locks == NONE,
 * chain_name == NULL. */
static void default_values(void **state)
{
    struct bf_lock lock = bf_lock_default();

    (void)state;

    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);
    assert_int_equal(lock.pindir_lock, BF_LOCK_NONE);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);
}

/* ------------------------------------------------------------------
 * bf_lock_init()
 * ------------------------------------------------------------------ */

/* Success post: bpffs_fd and pindir_fd are valid, pindir_lock == mode. */
static void init_success_post_state(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_READ));
    assert_fd(lock.bpffs_fd);
    assert_fd(lock.pindir_fd);
    assert_int_equal(lock.pindir_lock, BF_LOCK_READ);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);

    /* The pindir is created lazily. */
    assert_dir_exists(tmpdir, "bpfilter");
}

/* Failure post: on failure, `lock` is unchanged. */
static void init_failure_preserves_lock(void **state)
{
    _clean_bf_lock_ struct bf_lock holder = bf_lock_default();
    struct bf_lock lock = bf_lock_default();

    (void)state;

    /* Hold WRITE on the pindir so a second WRITE init will fail. */
    assert_ok(bf_lock_init(&holder, bft_state_tmpdir(*state)->dir_path,
                           BF_LOCK_WRITE));

    assert_err(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));

    /* lock is unchanged (still in default state). */
    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);
    assert_int_equal(lock.pindir_lock, BF_LOCK_NONE);
}

/* ------------------------------------------------------------------
 * flock matrix: WRITE / READ / NONE compatibility
 * ------------------------------------------------------------------ */

static void pindir_lock_matrix(void **state)
{
    (void)state;

    {
        // WRITE exclude other WRITE and READ
        _clean_bf_lock_ struct bf_lock lock1 = bf_lock_default();
        _clean_bf_lock_ struct bf_lock lock2 = bf_lock_default();

        assert_ok(bf_lock_init(&lock1, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_WRITE));
        assert_err(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                                BF_LOCK_WRITE));
        assert_err(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                                BF_LOCK_READ));
        assert_ok(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_NONE));
    }

    {
        // READ exclude WRITE
        _clean_bf_lock_ struct bf_lock lock1 = bf_lock_default();
        _clean_bf_lock_ struct bf_lock lock2 = bf_lock_default();

        assert_ok(bf_lock_init(&lock1, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_READ));
        assert_err(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                                BF_LOCK_WRITE));
        assert_ok(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_READ));
        assert_ok(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_NONE));
    }

    {
        // NONE allows all
        _clean_bf_lock_ struct bf_lock lock1 = bf_lock_default();
        _clean_bf_lock_ struct bf_lock lock2 = bf_lock_default();
        _clean_bf_lock_ struct bf_lock lock3 = bf_lock_default();

        assert_ok(bf_lock_init(&lock1, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_NONE));

        assert_ok(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_WRITE));
        bf_lock_cleanup(&lock2);

        assert_ok(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_READ));
        bf_lock_cleanup(&lock2);
    }
}

/* After cleanup, the pindir is still present on disk (never rmdir'd by
 * the library). Multiple init/cleanup cycles never remove the pindir. */
static void pindir_survives_repeated_cycles(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);

    for (int i = 0; i < 5; ++i) {
        struct bf_lock lock = bf_lock_default();

        assert_ok(bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_READ));
        bf_lock_cleanup(&lock);
        assert_dir_exists(tmpdir, "bpfilter");
    }
}

/* ------------------------------------------------------------------
 * bf_lock_acquire_chain()
 * ------------------------------------------------------------------ */

/* Invalid lock (default state) => -EBADFD; lock unchanged. */
static void acquire_chain_uninitialized_rejects(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
    struct bf_lock lock = bf_lock_default();

    // Pindir not locked, can't acquire a chain
    assert_err(bf_lock_acquire_chain(&lock, "c", BF_LOCK_READ, false));
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);
    assert_dir_not_exists(tmpdir, "bpfilter/c");
}

/* Can't lock a chain twice */
static void acquire_chain_double_rejects(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));
    assert_ok(bf_lock_acquire_chain(&lock, "first", BF_LOCK_WRITE, true));
    assert_dir_exists(tmpdir, "bpfilter/first");

    // Try to acquire the same chain again
    assert_err(bf_lock_acquire_chain(&lock, "first", BF_LOCK_WRITE, true));

    // Try to acquire another chain
    assert_err(bf_lock_acquire_chain(&lock, "second", BF_LOCK_WRITE, true));
    assert_dir_not_exists(tmpdir, "bpfilter/second");
}

/* Chain dir is created when WRITE is used */
static void acquire_chain_create(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));

    // Acquire with READ and create=true fails
    assert_err(bf_lock_acquire_chain(&lock, "c", BF_LOCK_READ, true));
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_dir_not_exists(tmpdir, "bpfilter/c");

    // Acquire with WRITE and create=true (empty chain dir is removed)
    assert_ok(bf_lock_acquire_chain(&lock, "c", BF_LOCK_WRITE, true));
    assert_fd(lock.chain_fd);
    assert_string_equal(lock.chain_name, "c");
    assert_dir_exists(tmpdir, "bpfilter/c");

    bf_lock_release_chain(&lock);
    assert_dir_not_exists(tmpdir, "bpfilter/c");
}

/* Can't lock a non-existing chain without create=true */
static void acquire_chain_missing_fails(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_READ));
    assert_err(bf_lock_acquire_chain(&lock, "absent", BF_LOCK_READ, false));
    assert_dir_not_exists(tmpdir, "bpfilter/absent");
}

/* ------------------------------------------------------------------
 * Chain-level flock matrix
 * ------------------------------------------------------------------ */

/* Two READ chain locks on the same chain are compatible. */
static void chain_read_compatible_read(void **state)
{
    _clean_bf_lock_ struct bf_lock lock1 = bf_lock_default();
    _clean_bf_lock_ struct bf_lock lock2 = bf_lock_default();

    (void)state;

    {
        _clean_bf_lock_ struct bf_lock prep = bf_lock_default();
        assert_ok(bf_lock_init(&prep, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_WRITE));
        assert_ok(bf_lock_acquire_chain(&prep, "shared", BF_LOCK_WRITE, true));
        (void)mknodat(prep.chain_fd, "keepalive", S_IFREG | 0644, 0);
    }

    assert_ok(bf_lock_init_for_chain(&lock1, bft_state_tmpdir(*state)->dir_path,
                                     "shared", BF_LOCK_READ, BF_LOCK_READ,
                                     false));
    assert_ok(bf_lock_init_for_chain(&lock2, bft_state_tmpdir(*state)->dir_path,
                                     "shared", BF_LOCK_READ, BF_LOCK_READ,
                                     false));
}

/* Two locks on DIFFERENT chains are compatible, even when both hold WRITE.
 * `bf_ruleset_set` relies on this: it iterates per-chain WRITE locks while
 * holding the pindir WRITE, and each chain's flock must not contend with
 * the others. */
static void chain_lock_isolates_per_chain(void **state)
{
    _clean_bf_lock_ struct bf_lock lock_a = bf_lock_default();
    _clean_bf_lock_ struct bf_lock lock_b = bf_lock_default();

    (void)state;

    /* Materialise both chains so they can be opened with create=false. */
    {
        _clean_bf_lock_ struct bf_lock prep = bf_lock_default();
        assert_ok(bf_lock_init(&prep, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_WRITE));
        assert_ok(bf_lock_acquire_chain(&prep, "alpha", BF_LOCK_WRITE, true));
        (void)mknodat(prep.chain_fd, "keepalive", S_IFREG | 0644, 0);

        bf_lock_release_chain(&prep);
        assert_ok(bf_lock_acquire_chain(&prep, "beta", BF_LOCK_WRITE, true));
        (void)mknodat(prep.chain_fd, "keepalive", S_IFREG | 0644, 0);
    }

    assert_ok(
        bf_lock_init_for_chain(&lock_a, bft_state_tmpdir(*state)->dir_path,
                               "alpha", BF_LOCK_READ, BF_LOCK_WRITE, false));
    assert_string_equal(lock_a.chain_name, "alpha");
    assert_int_equal(lock_a.chain_lock, BF_LOCK_WRITE);

    /* Independent chain: WRITE on "beta" must not contend with WRITE on
     * "alpha". */
    assert_ok(bf_lock_init_for_chain(&lock_b,
                                     bft_state_tmpdir(*state)->dir_path, "beta",
                                     BF_LOCK_READ, BF_LOCK_WRITE, false));
    assert_string_equal(lock_b.chain_name, "beta");
    assert_int_equal(lock_b.chain_lock, BF_LOCK_WRITE);
}

/* ------------------------------------------------------------------
 * bf_lock_release_chain() post-conditions (I2)
 * ------------------------------------------------------------------ */

/* `bf_lock_release_chain` is idempotent: calling it twice in a row is a
 * silent no-op for the second call. Calling it on a default-initialised
 * lock (no fds at all) is also a no-op (modulo a warning). The caller
 * relies on this for `_clean_bf_lock_` correctness when an early failure
 * leaves the lock partially populated. */
static void release_chain_idempotent(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    /* Default lock: silent no-op, fields stay defaulted. */
    bf_lock_release_chain(&lock);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);

    /* Initialised lock with no chain held: still a no-op, twice. */
    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));
    bf_lock_release_chain(&lock);
    bf_lock_release_chain(&lock);
    assert_fd(lock.pindir_fd);
    assert_int_equal(lock.pindir_lock, BF_LOCK_WRITE);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);

    /* Acquire + release + release again: the second release must be a
     * no-op and not double-close the chain fd or double-free chain_name. */
    assert_ok(bf_lock_acquire_chain(&lock, "idempotent", BF_LOCK_WRITE, true));
    bf_lock_release_chain(&lock);
    bf_lock_release_chain(&lock);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);
}

/* Acquire then release then re-acquire on the same `bf_lock`: the second
 * acquire must succeed and fully populate the chain fields. */
static void release_then_reacquire(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));

    assert_ok(bf_lock_acquire_chain(&lock, "first", BF_LOCK_WRITE, true));
    assert_string_equal(lock.chain_name, "first");
    assert_fd(lock.chain_fd);
    assert_int_equal(lock.chain_lock, BF_LOCK_WRITE);

    bf_lock_release_chain(&lock);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);

    /* Re-acquire on the same lock: must succeed and update all chain
     * fields, including the new name. */
    assert_ok(bf_lock_acquire_chain(&lock, "second", BF_LOCK_WRITE, true));
    assert_string_equal(lock.chain_name, "second");
    assert_fd(lock.chain_fd);
    assert_int_equal(lock.chain_lock, BF_LOCK_WRITE);

    /* The pindir lock must be unchanged across the release/reacquire. */
    assert_int_equal(lock.pindir_lock, BF_LOCK_WRITE);
}

/* `BF_LOCK_NONE` on the chain side opens the chain dir without taking an
 * `flock`. The chain dir must be observable as locked-with-NONE in the
 * post-state, and `bf_lock_release_chain` must NOT try to remove it (the
 * removal gate is `chain_lock == BF_LOCK_WRITE`). */
static void chain_lock_none_acquire_and_release(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    /* Pre-create the chain dir; we'll open it with chain mode == NONE. */
    {
        _clean_bf_lock_ struct bf_lock prep = bf_lock_default();
        assert_ok(bf_lock_init(&prep, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_WRITE));
        assert_ok(
            bf_lock_acquire_chain(&prep, "none_chain", BF_LOCK_WRITE, true));
        (void)mknodat(prep.chain_fd, "keepalive", S_IFREG | 0644, 0);
    }

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_READ));
    assert_ok(bf_lock_acquire_chain(&lock, "none_chain", BF_LOCK_NONE, false));

    /* Because chain_lock != WRITE, release must NOT remove the chain dir,
     * even if it were empty. */
    bf_lock_release_chain(&lock);
    assert_dir_exists(tmpdir, "bpfilter/none_chain");
}

/* No-op on a lock with no chain held. */
static void release_no_chain_is_noop(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_READ));
    bf_lock_release_chain(&lock);

    /* Pindir state untouched. */
    assert_fd(lock.pindir_fd);
    assert_int_equal(lock.pindir_lock, BF_LOCK_READ);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);
}

/* WRITE release removes an empty chain dir; the chain fields are reset. */
static void release_write_removes_empty_chain(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));
    assert_ok(bf_lock_acquire_chain(&lock, "empty", BF_LOCK_WRITE, true));
    assert_dir_exists(tmpdir, "bpfilter/empty");

    bf_lock_release_chain(&lock);

    /* Empty chain dir was removed. */
    assert_dir_not_exists(tmpdir, "bpfilter/empty");
    /* Chain fields reset. */
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);
    /* Pindir state still valid. */
    assert_fd(lock.pindir_fd);
    assert_int_equal(lock.pindir_lock, BF_LOCK_WRITE);
}

/* WRITE release does NOT remove a non-empty chain dir. */
static void release_write_keeps_nonempty_chain(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));
    assert_ok(bf_lock_acquire_chain(&lock, "populated", BF_LOCK_WRITE, true));
    /* Populate so rmdir returns ENOTEMPTY and no-ops. */
    (void)mknodat(lock.chain_fd, "inside", S_IFREG | 0644, 0);

    bf_lock_release_chain(&lock);

    assert_dir_exists(tmpdir, "bpfilter/populated");
}

/* READ release does NOT remove the chain dir (I2). */
static void release_read_keeps_chain(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    /* Create and populate so an accidental rmdir would fail silently (we
     * really want to know the *code path* isn't even trying). We still
     * observe via the "chain stays" invariant. */
    {
        _clean_bf_lock_ struct bf_lock prep = bf_lock_default();
        assert_ok(bf_lock_init(&prep, bft_state_tmpdir(*state)->dir_path,
                               BF_LOCK_WRITE));
        assert_ok(bf_lock_acquire_chain(&prep, "reader", BF_LOCK_WRITE, true));
        (void)mknodat(prep.chain_fd, "keepalive", S_IFREG | 0644, 0);
    }

    assert_ok(bf_lock_init_for_chain(&lock, bft_state_tmpdir(*state)->dir_path,
                                     "reader", BF_LOCK_READ, BF_LOCK_READ,
                                     false));

    bf_lock_release_chain(&lock);
    assert_dir_exists(tmpdir, "bpfilter/reader");
}

/* ------------------------------------------------------------------
 * bf_lock_cleanup()
 * ------------------------------------------------------------------ */

/* Cleanup is idempotent and safe on a default lock. */
static void cleanup_idempotent(void **state)
{
    struct bf_lock lock = bf_lock_default();

    (void)state;

    bf_lock_cleanup(&lock);
    bf_lock_cleanup(&lock);
    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_READ));
    bf_lock_cleanup(&lock);
    bf_lock_cleanup(&lock);

    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);
    assert_int_equal(lock.pindir_lock, BF_LOCK_NONE);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
    assert_int_equal(lock.chain_lock, BF_LOCK_NONE);
}

/* Cleanup releases the pindir lock so another caller can immediately
 * acquire it. */
static void cleanup_releases_pindir_lock(void **state)
{
    struct bf_lock lock1 = bf_lock_default();
    _clean_bf_lock_ struct bf_lock lock2 = bf_lock_default();

    (void)state;

    assert_ok(bf_lock_init(&lock1, bft_state_tmpdir(*state)->dir_path,
                           BF_LOCK_WRITE));
    bf_lock_cleanup(&lock1);

    assert_ok(bf_lock_init(&lock2, bft_state_tmpdir(*state)->dir_path,
                           BF_LOCK_WRITE));
}

/* Cleanup on a lock holding a chain WRITE lock releases both locks and
 * removes the empty chain dir; the pindir itself is kept (I1). */
static void cleanup_with_chain_lock(void **state)
{
    struct bft_tmpdir *tmpdir = bft_state_tmpdir(*state);
    struct bf_lock lock = bf_lock_default();

    assert_ok(
        bf_lock_init(&lock, bft_state_tmpdir(*state)->dir_path, BF_LOCK_WRITE));
    assert_ok(bf_lock_acquire_chain(&lock, "c", BF_LOCK_WRITE, true));
    assert_dir_exists(tmpdir, "bpfilter/c");

    bf_lock_cleanup(&lock);

    /* Chain dir removed (empty), pindir kept (I1). */
    assert_dir_not_exists(tmpdir, "bpfilter/c");
    assert_dir_exists(tmpdir, "bpfilter");
    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);
    assert_int_equal(lock.chain_fd, -1);
}

/* ------------------------------------------------------------------
 * bf_lock_init_for_chain()
 * ------------------------------------------------------------------ */

/* Reject create=true with pindir_mode != WRITE. */
static void init_for_chain_create_needs_write_pindir(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    assert_int_equal(
        bf_lock_init_for_chain(&lock, bft_state_tmpdir(*state)->dir_path, "c",
                               BF_LOCK_READ, BF_LOCK_WRITE, true),
        -EINVAL);
    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
}

/* Reject create=true with chain mode != WRITE. */
static void init_for_chain_create_needs_write_chain(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    assert_int_equal(
        bf_lock_init_for_chain(&lock, bft_state_tmpdir(*state)->dir_path, "c",
                               BF_LOCK_WRITE, BF_LOCK_READ, true),
        -EINVAL);
    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);
}

/* Success: locks both dirs with the requested modes. */
static void init_for_chain_success(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    assert_ok(bf_lock_init_for_chain(&lock, bft_state_tmpdir(*state)->dir_path,
                                     "both", BF_LOCK_WRITE, BF_LOCK_WRITE,
                                     true));
    assert_fd(lock.bpffs_fd);
    assert_fd(lock.pindir_fd);
    assert_int_equal(lock.pindir_lock, BF_LOCK_WRITE);
    assert_fd(lock.chain_fd);
    assert_string_equal(lock.chain_name, "both");
    assert_int_equal(lock.chain_lock, BF_LOCK_WRITE);
}

/* Failure preserves the lock in default state. */
static void init_for_chain_failure_preserves_lock(void **state)
{
    _clean_bf_lock_ struct bf_lock lock = bf_lock_default();

    (void)state;

    /* Missing chain, create=false. */
    assert_int_equal(
        bf_lock_init_for_chain(&lock, bft_state_tmpdir(*state)->dir_path,
                               "absent", BF_LOCK_READ, BF_LOCK_READ, false),
        -ENOENT);
    assert_int_equal(lock.bpffs_fd, -1);
    assert_int_equal(lock.pindir_fd, -1);
    assert_int_equal(lock.chain_fd, -1);
    assert_null(lock.chain_name);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(default_values),

        cmocka_unit_test_setup_teardown(init_success_post_state,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(init_failure_preserves_lock,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(pindir_lock_matrix, bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(pindir_survives_repeated_cycles,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(acquire_chain_uninitialized_rejects,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(acquire_chain_double_rejects,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(chain_read_compatible_read,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(chain_lock_isolates_per_chain,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(chain_lock_none_acquire_and_release,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(release_chain_idempotent,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(release_then_reacquire,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(release_no_chain_is_noop,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(release_write_removes_empty_chain,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(release_write_keeps_nonempty_chain,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(release_read_keeps_chain,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(cleanup_idempotent, bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(cleanup_releases_pindir_lock,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(cleanup_with_chain_lock,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(
            init_for_chain_create_needs_write_pindir, bft_setup_ctx_state,
            bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(init_for_chain_create_needs_write_chain,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(init_for_chain_success,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(init_for_chain_failure_preserves_lock,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(acquire_chain_missing_fails,
                                        bft_setup_ctx_state,
                                        bft_teardown_ctx_state),
        cmocka_unit_test_setup_teardown(
            acquire_chain_create, bft_setup_ctx_state, bft_teardown_ctx_state),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
