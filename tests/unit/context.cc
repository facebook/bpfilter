#include <gtest/gtest.h>

extern "C" {
#include "core/context.h"
}

TEST(context, init_and_clean)
{
    struct bf_context c;

    bf_context_init(&c);
    bf_context_clean(&c);
}

TEST(context, ensure_reject_null_params)
{
    EXPECT_DEATH(bf_context_init(nullptr), "");
}
