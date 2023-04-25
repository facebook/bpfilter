#include <gtest/gtest.h>

extern "C" {
#include <errno.h>

/* libstdc++ requires _GNU_SOURCE to be defined, so it defines it. This leads
 * to:
 *	warning: "_GNU_SOURCE" redefined
 * from GCC. Undefine it before including core/map.h (which defines it also)
 * to get rid of this message.
 * See https://gcc.gnu.org/onlinedocs/libstdc++/faq.html#faq.predefined for
 * more details. */
#undef _GNU_SOURCE
#include "core/map.h"
}


TEST(map, init_and_clean)
{
	bf_map *map;

	EXPECT_EQ(0, bf_map_new(&map, 0));
	EXPECT_NE(nullptr, map);

	bf_map_free(&map);
	EXPECT_EQ(nullptr, map);

	EXPECT_EQ(0, bf_map_new(&map, 10));
	EXPECT_NE(nullptr, map);

	bf_map_free(&map);
	EXPECT_EQ(nullptr, map);
}

TEST(map, insert_and_search)
{
	bf_map *map;
	void *value = nullptr;

	EXPECT_EQ(0, bf_map_new(&map, 10));

	// Look for non-existing key
	EXPECT_EQ(-ENOENT, bf_map_find(map, "hello", &value));
	EXPECT_EQ(nullptr, value);

	// Look for existing key
	EXPECT_EQ(0, bf_map_upsert(map, "hello", (void *)0x5));
	EXPECT_EQ(0, bf_map_find(map, "hello", &value));
	EXPECT_EQ((void *)0x5, value);

	// Replace existing key/value
	EXPECT_EQ(0, bf_map_upsert(map, "hello", (void *)0x17));
	EXPECT_EQ(0, bf_map_find(map, "hello", &value));
	EXPECT_EQ((void *)0x17, value);

	bf_map_free(&map);
}

TEST(map, ensure_reject_null_params)
{
    EXPECT_DEATH(bf_map_new(nullptr, 0), "");
    EXPECT_DEATH(bf_map_free(nullptr), "");
    EXPECT_DEATH(bf_map_find(nullptr, nullptr, nullptr), "");
    EXPECT_DEATH(bf_map_upsert(nullptr, nullptr, nullptr), "");
}
