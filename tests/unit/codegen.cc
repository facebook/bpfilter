#include <cerrno>
#include <gtest/gtest.h>

extern "C" {
#include "external/filter.h"
#include "generator/codegen.h"
}

TEST(codegen, avoid_insn_overflow)
{
    int r;

    {
        __cleanup_bf_codegen__ bf_codegen *codegen = nullptr;
        EXPECT_EQ(0, r = bf_codegen_new(&codegen));
        for (int i = 0; i < BF_CODEGEN_MAX_INSN; ++i) {
            EXPECT_EQ(0, EMIT(codegen, BPF_MOV64_REG(BPF_REG_0, BPF_REG_1)));
        }
        EXPECT_EQ(-EOVERFLOW,
                  EMIT(codegen, BPF_MOV64_REG(BPF_REG_0, BPF_REG_1)));
    }

    {
        __cleanup_bf_codegen__ bf_codegen *codegen = nullptr;
        EXPECT_EQ(0, r = bf_codegen_new(&codegen));
        for (int i = 0; i < BF_CODEGEN_MAX_INSN; ++i) {
            EXPECT_EQ(0, EMIT(codegen, BPF_MOV64_REG(BPF_REG_0, BPF_REG_1)));
        }
        EXPECT_EQ(-EOVERFLOW,
                  EMIT_FIXUP(codegen, BF_CODEGEN_FIXUP_END_OF_CHAIN,
                             BPF_JMP_REG(BPF_JGT, CODEGEN_REG_SCRATCH1,
                                         CODEGEN_REG_DATA_END, 0)));
    }
}
