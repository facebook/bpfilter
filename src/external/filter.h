/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linux Socket Filter Data Structures
 */
#ifndef __LINUX_FILTER_H__
#define __LINUX_FILTER_H__

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stdbool.h>

/* ArgX, context and stack frame pointer register positions. Note,
 * Arg1, Arg2, Arg3, etc are used as argument mappings of function
 * calls in BPF_CALL instruction.
 */
#define BPF_REG_ARG1 BPF_REG_1
#define BPF_REG_ARG2 BPF_REG_2
#define BPF_REG_ARG3 BPF_REG_3
#define BPF_REG_ARG4 BPF_REG_4
#define BPF_REG_ARG5 BPF_REG_5
#define BPF_REG_CTX BPF_REG_6
#define BPF_REG_FP BPF_REG_10

/* Additional register mappings for converted user programs. */
#define BPF_REG_A BPF_REG_0
#define BPF_REG_X BPF_REG_7
#define BPF_REG_TMP BPF_REG_2 /* scratch reg */
#define BPF_REG_D BPF_REG_8 /* data, callee-saved */
#define BPF_REG_H BPF_REG_9 /* hlen, callee-saved */

/* Kernel hidden auxiliary/helper register. */
#define BPF_REG_AX MAX_BPF_REG
#define MAX_BPF_EXT_REG (MAX_BPF_REG + 1)
#define MAX_BPF_JIT_REG MAX_BPF_EXT_REG

/* unused opcode to mark special call to bpf_tail_call() helper */
#define BPF_TAIL_CALL 0xf0

/* unused opcode to mark special load instruction. Same as BPF_ABS */
#define BPF_PROBE_MEM 0x20

/* unused opcode to mark call to interpreter with arguments */
#define BPF_CALL_ARGS 0xe0

/* unused opcode to mark speculation barrier for mitigating
 * Speculative Store Bypass
 */
#define BPF_NOSPEC 0xc0

/* As per nm, we expose JITed images as text (code) section for
 * kallsyms. That way, tools like perf can find it to match
 * addresses.
 */
#define BPF_SYM_ELF_TYPE 't'

/* BPF program can access up to 512 bytes of stack space. */
#define MAX_BPF_STACK 512

/* Helper macros for filter block array initializers. */

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn) {.code = BPF_ALU64 | BPF_OP(OP) | BPF_X,                \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = 0})

#define BPF_ALU32_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn) {.code = BPF_ALU | BPF_OP(OP) | BPF_X,                  \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = 0})

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn) {.code = BPF_ALU64 | BPF_OP(OP) | BPF_K,                \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = IMM})

#define BPF_ALU32_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn) {.code = BPF_ALU | BPF_OP(OP) | BPF_K,                  \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = IMM})

/* Endianess conversion, cpu_to_{l,b}e(), {l,b}e_to_cpu() */

#define BPF_ENDIAN(TYPE, DST, LEN)                                             \
    ((struct bpf_insn) {.code = BPF_ALU | BPF_END | BPF_SRC(TYPE),             \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = LEN})

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)                                                \
    ((struct bpf_insn) {.code = BPF_ALU64 | BPF_MOV | BPF_X,                   \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = 0})

#define BPF_MOV32_REG(DST, SRC)                                                \
    ((struct bpf_insn) {.code = BPF_ALU | BPF_MOV | BPF_X,                     \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = 0})

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)                                                \
    ((struct bpf_insn) {.code = BPF_ALU64 | BPF_MOV | BPF_K,                   \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = IMM})

#define BPF_MOV32_IMM(DST, IMM)                                                \
    ((struct bpf_insn) {.code = BPF_ALU | BPF_MOV | BPF_K,                     \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = IMM})

/* Special form of mov32, used for doing explicit zero extension on dst. */
#define BPF_ZEXT_REG(DST)                                                      \
    ((struct bpf_insn) {.code = BPF_ALU | BPF_MOV | BPF_X,                     \
                        .dst_reg = DST,                                        \
                        .src_reg = DST,                                        \
                        .off = 0,                                              \
                        .imm = 1})

static inline bool insn_is_zext(const struct bpf_insn *insn)
{
    return insn->code == (BPF_ALU | BPF_MOV | BPF_X) && insn->imm == 1;
}

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM) BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                                        \
    ((struct bpf_insn) {.code = BPF_LD | BPF_DW | BPF_IMM,                     \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = (__u32)(IMM)}),                                 \
        ((struct bpf_insn) {.code = 0, /* zero is reserved opcode */           \
                            .dst_reg = 0,                                      \
                            .src_reg = 0,                                      \
                            .off = 0,                                          \
                            .imm = ((__u64)(IMM)) >> 32})

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)                                             \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Short form of mov based on type, BPF_X: dst_reg = src_reg, BPF_K: dst_reg =
 * imm32 */

#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)                                     \
    ((struct bpf_insn) {.code = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),           \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = IMM})

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)                                     \
    ((struct bpf_insn) {.code = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),             \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = IMM})

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)                                                  \
    ((struct bpf_insn) {.code = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,             \
                        .dst_reg = 0,                                          \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = IMM})

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */

#define BPF_LD_IND(SIZE, SRC, IMM)                                             \
    ((struct bpf_insn) {.code = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,             \
                        .dst_reg = 0,                                          \
                        .src_reg = SRC,                                        \
                        .off = 0,                                              \
                        .imm = IMM})

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn) {.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,            \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = OFF,                                            \
                        .imm = 0})

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn) {.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,            \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = OFF,                                            \
                        .imm = 0})

/*
 * Atomic operations:
 *
 *   BPF_ADD                  *(uint *) (dst_reg + off16) += src_reg
 *   BPF_AND                  *(uint *) (dst_reg + off16) &= src_reg
 *   BPF_OR                   *(uint *) (dst_reg + off16) |= src_reg
 *   BPF_XOR                  *(uint *) (dst_reg + off16) ^= src_reg
 *   BPF_ADD | BPF_FETCH      src_reg = atomic_fetch_add(dst_reg + off16,
 * src_reg); BPF_AND | BPF_FETCH      src_reg = atomic_fetch_and(dst_reg +
 * off16, src_reg); BPF_OR | BPF_FETCH       src_reg = atomic_fetch_or(dst_reg +
 * off16, src_reg); BPF_XOR | BPF_FETCH      src_reg = atomic_fetch_xor(dst_reg
 * + off16, src_reg); BPF_XCHG                 src_reg = atomic_xchg(dst_reg +
 * off16, src_reg) BPF_CMPXCHG              r0 = atomic_cmpxchg(dst_reg + off16,
 * r0, src_reg)
 */

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)                                 \
    ((struct bpf_insn) {.code = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,         \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = OFF,                                            \
                        .imm = OP})

/* Legacy alias */
#define BPF_STX_XADD(SIZE, DST, SRC, OFF)                                      \
    BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                                        \
    ((struct bpf_insn) {.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,             \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = OFF,                                            \
                        .imm = IMM})

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc +
 * off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)                                         \
    ((struct bpf_insn) {.code = BPF_JMP | BPF_OP(OP) | BPF_X,                  \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = OFF,                                            \
                        .imm = 0})

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16
 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                         \
    ((struct bpf_insn) {.code = BPF_JMP | BPF_OP(OP) | BPF_K,                  \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = OFF,                                            \
                        .imm = IMM})

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)                                       \
    ((struct bpf_insn) {.code = BPF_JMP32 | BPF_OP(OP) | BPF_X,                \
                        .dst_reg = DST,                                        \
                        .src_reg = SRC,                                        \
                        .off = OFF,                                            \
                        .imm = 0})

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                                       \
    ((struct bpf_insn) {.code = BPF_JMP32 | BPF_OP(OP) | BPF_K,                \
                        .dst_reg = DST,                                        \
                        .src_reg = 0,                                          \
                        .off = OFF,                                            \
                        .imm = IMM})

/* Unconditional jumps, goto pc + off16 */

#define BPF_JMP_A(OFF)                                                         \
    ((struct bpf_insn) {.code = BPF_JMP | BPF_JA,                              \
                        .dst_reg = 0,                                          \
                        .src_reg = 0,                                          \
                        .off = OFF,                                            \
                        .imm = 0})

/* Relative call */

#define BPF_CALL_REL(TGT)                                                      \
    ((struct bpf_insn) {.code = BPF_JMP | BPF_CALL,                            \
                        .dst_reg = 0,                                          \
                        .src_reg = BPF_PSEUDO_CALL,                            \
                        .off = 0,                                              \
                        .imm = TGT})

/* Convert function address to BPF immediate */

#define BPF_EMIT_CALL(FUNC)                                                    \
    ((struct bpf_insn) {.code = BPF_JMP | BPF_CALL,                            \
                        .dst_reg = 0,                                          \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = FUNC})

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)                                 \
    ((struct bpf_insn) {                                                       \
        .code = CODE, .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = IMM})

/* Program exit */

#define BPF_EXIT_INSN()                                                        \
    ((struct bpf_insn) {.code = BPF_JMP | BPF_EXIT,                            \
                        .dst_reg = 0,                                          \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = 0})

/* Speculation barrier */

#define BPF_ST_NOSPEC()                                                        \
    ((struct bpf_insn) {.code = BPF_ST | BPF_NOSPEC,                           \
                        .dst_reg = 0,                                          \
                        .src_reg = 0,                                          \
                        .off = 0,                                              \
                        .imm = 0})

/* Internal classic blocks for direct assignment */

#define __BPF_STMT(CODE, K) ((struct sock_filter)BPF_STMT(CODE, K))

#define __BPF_JUMP(CODE, K, JT, JF)                                            \
    ((struct sock_filter)BPF_JUMP(CODE, K, JT, JF))

#define bytes_to_bpf_size(bytes)                                               \
    ({                                                                         \
        int bpf_size = -EINVAL;                                                \
                                                                               \
        if (bytes == sizeof(u8))                                               \
            bpf_size = BPF_B;                                                  \
        else if (bytes == sizeof(u16))                                         \
            bpf_size = BPF_H;                                                  \
        else if (bytes == sizeof(u32))                                         \
            bpf_size = BPF_W;                                                  \
        else if (bytes == sizeof(u64))                                         \
            bpf_size = BPF_DW;                                                 \
                                                                               \
        bpf_size;                                                              \
    })

#define bpf_size_to_bytes(bpf_size)                                            \
    ({                                                                         \
        int bytes = -EINVAL;                                                   \
                                                                               \
        if (bpf_size == BPF_B)                                                 \
            bytes = sizeof(u8);                                                \
        else if (bpf_size == BPF_H)                                            \
            bytes = sizeof(u16);                                               \
        else if (bpf_size == BPF_W)                                            \
            bytes = sizeof(u32);                                               \
        else if (bpf_size == BPF_DW)                                           \
            bytes = sizeof(u64);                                               \
                                                                               \
        bytes;                                                                 \
    })

#define BPF_SIZEOF(type)                                                       \
    ({                                                                         \
        const int __size = bytes_to_bpf_size(sizeof(type));                    \
        BUILD_BUG_ON(__size < 0);                                              \
        __size;                                                                \
    })

#define BPF_FIELD_SIZEOF(type, field)                                          \
    ({                                                                         \
        const int __size = bytes_to_bpf_size(sizeof_field(type, field));       \
        BUILD_BUG_ON(__size < 0);                                              \
        __size;                                                                \
    })

#define BPF_LDST_BYTES(insn)                                                   \
    ({                                                                         \
        const int __size = bpf_size_to_bytes(BPF_SIZE((insn)->code));          \
        WARN_ON(__size < 0);                                                   \
        __size;                                                                \
    })

#define __BPF_MAP_0(m, v, ...) v
#define __BPF_MAP_1(m, v, t, a, ...) m(t, a)
#define __BPF_MAP_2(m, v, t, a, ...) m(t, a), __BPF_MAP_1(m, v, __VA_ARGS__)
#define __BPF_MAP_3(m, v, t, a, ...) m(t, a), __BPF_MAP_2(m, v, __VA_ARGS__)
#define __BPF_MAP_4(m, v, t, a, ...) m(t, a), __BPF_MAP_3(m, v, __VA_ARGS__)
#define __BPF_MAP_5(m, v, t, a, ...) m(t, a), __BPF_MAP_4(m, v, __VA_ARGS__)

#define __BPF_REG_0(...) __BPF_PAD(5)
#define __BPF_REG_1(...) __BPF_MAP(1, __VA_ARGS__), __BPF_PAD(4)
#define __BPF_REG_2(...) __BPF_MAP(2, __VA_ARGS__), __BPF_PAD(3)
#define __BPF_REG_3(...) __BPF_MAP(3, __VA_ARGS__), __BPF_PAD(2)
#define __BPF_REG_4(...) __BPF_MAP(4, __VA_ARGS__), __BPF_PAD(1)
#define __BPF_REG_5(...) __BPF_MAP(5, __VA_ARGS__)

#define __BPF_MAP(n, ...) __BPF_MAP_##n(__VA_ARGS__)
#define __BPF_REG(n, ...) __BPF_REG_##n(__VA_ARGS__)

#define __BPF_CAST(t, a)                                                       \
    (__force t)(__force typeof(__builtin_choose_expr(                          \
        sizeof(t) == sizeof(unsigned long), (unsigned long)0, (t)0))) a
#define __BPF_V void
#define __BPF_N

#define __BPF_DECL_ARGS(t, a) t a
#define __BPF_DECL_REGS(t, a) u64 a

#define __BPF_PAD(n)                                                           \
    __BPF_MAP(n, __BPF_DECL_ARGS, __BPF_N, u64, __ur_1, u64, __ur_2, u64,      \
              __ur_3, u64, __ur_4, u64, __ur_5)

#define BPF_CALL_x(x, name, ...)                                               \
    static __always_inline u64 ____##name(                                     \
        __BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__));                  \
    typedef u64 (*btf_##name)(                                                 \
        __BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__));                  \
    u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));             \
    u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))              \
    {                                                                          \
        return ((btf_##name)____##name)(                                       \
            __BPF_MAP(x, __BPF_CAST, __BPF_N, __VA_ARGS__));                   \
    }                                                                          \
    static __always_inline u64 ____##name(                                     \
        __BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))

#define BPF_CALL_0(name, ...) BPF_CALL_x(0, name, __VA_ARGS__)
#define BPF_CALL_1(name, ...) BPF_CALL_x(1, name, __VA_ARGS__)
#define BPF_CALL_2(name, ...) BPF_CALL_x(2, name, __VA_ARGS__)
#define BPF_CALL_3(name, ...) BPF_CALL_x(3, name, __VA_ARGS__)
#define BPF_CALL_4(name, ...) BPF_CALL_x(4, name, __VA_ARGS__)
#define BPF_CALL_5(name, ...) BPF_CALL_x(5, name, __VA_ARGS__)

#define bpf_ctx_range(TYPE, MEMBER)                                            \
    offsetof(TYPE, MEMBER)... offsetofend(TYPE, MEMBER) - 1
#define bpf_ctx_range_till(TYPE, MEMBER1, MEMBER2)                             \
    offsetof(TYPE, MEMBER1)... offsetofend(TYPE, MEMBER2) - 1
#if BITS_PER_LONG == 64
#define bpf_ctx_range_ptr(TYPE, MEMBER)                                        \
    offsetof(TYPE, MEMBER)... offsetofend(TYPE, MEMBER) - 1
#else
#define bpf_ctx_range_ptr(TYPE, MEMBER)                                        \
    offsetof(TYPE, MEMBER)... offsetof(TYPE, MEMBER) + 8 - 1
#endif /* BITS_PER_LONG == 64 */

#define bpf_target_off(TYPE, MEMBER, SIZE, PTR_SIZE)                           \
    ({                                                                         \
        BUILD_BUG_ON(sizeof_field(TYPE, MEMBER) != (SIZE));                    \
        *(PTR_SIZE) = (SIZE);                                                  \
        offsetof(TYPE, MEMBER);                                                \
    })

#endif /* __LINUX_FILTER_H__ */
