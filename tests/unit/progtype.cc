#include <gtest/gtest.h>

extern "C" {
#include "generator/progtype.h"
}

TEST(progtype, bf_progtype_ops_get)
{
    for (size_t i = 0; i < __BF_PROGTYPE_MAX; i++)
        bf_progtype_ops_get(static_cast<enum bf_progtype>(i));
}

TEST(progtype, bf_progtype_to_str)
{
    for (size_t i = 0; i < __BF_PROGTYPE_MAX; i++)
        EXPECT_NE(nullptr,
                  bf_progtype_to_str(static_cast<enum bf_progtype>(i)));
}

TEST(progtype, bf_hook_to_progtype)
{
    for (size_t i = 0; i < __BF_HOOK_MAX; i++)
        EXPECT_NE(__BF_PROGTYPE_MAX,
                  bf_hook_to_progtype(static_cast<enum bf_hooks>(i)));
}
