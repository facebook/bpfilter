/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <memory>
#include <vector>

extern "C" {
#include <bpfilter/matcher.h>
}

namespace bf
{

class Matcher
{
private:
    struct deleter
    {
        void operator()(bf_matcher *ptr)
        {
            bf_matcher_free(&ptr);
        }
    };

    bf_matcher_type _type;
    bf_matcher_op _op;
    std::vector<uint8_t> _payload;
    bool _negate;

public:
    Matcher(bf_matcher_type type, bf_matcher_op op,
            std::vector<uint8_t> payload, bool negate = false):
        _type {type},
        _op {op},
        _payload {std::move(payload)},
        _negate {negate} {};

    [[nodiscard]] bf_matcher_type type() const
    {
        return _type;
    }

    [[nodiscard]] bf_matcher_op op() const
    {
        return _op;
    }

    [[nodiscard]] const std::vector<uint8_t> &payload() const
    {
        return _payload;
    }

    [[nodiscard]] bool negate() const
    {
        return _negate;
    }

    [[nodiscard]] std::unique_ptr<bf_matcher, deleter> get() const
    {
        struct bf_matcher *matcher = nullptr;

        int r = bf_matcher_new(&matcher, _type, _op, _payload.data(),
                               _payload.size());
        if (r != 0)
            throw std::runtime_error("failed to create bf_matcher");

        bf_matcher_set_negate(matcher, _negate);

        return std::unique_ptr<bf_matcher, deleter>(matcher);
    }
};

} // namespace bf
