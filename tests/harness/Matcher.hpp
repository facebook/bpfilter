/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

#include "Set.hpp"

extern "C" {
#include <bpfilter/chain.h>
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
    std::shared_ptr<const bf_set> _set;

public:
    Matcher(bf_matcher_type type, bf_matcher_op op,
            std::vector<uint8_t> payload, bool negate = false):
        _type {type},
        _op {op},
        _payload {std::move(payload)},
        _negate {negate} {};

    static Matcher in(const Set &set, bool negate = false)
    {
        Matcher matcher(BF_MATCHER_SET, BF_MATCHER_IN, {}, negate);

        matcher._set = set.ref();

        return matcher;
    }

    static Matcher alwaysMatch()
    {
        float probability = 100.0f;
        std::vector<uint8_t> payload(sizeof(probability));

        std::memcpy(payload.data(), &probability, sizeof(probability));
        return {BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ, std::move(payload)};
    }

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

    [[nodiscard]] std::unique_ptr<bf_matcher, deleter>
    get(const bf_chain *chain = nullptr) const
    {
        struct bf_matcher *matcher = nullptr;

        const bf_set *set = _set.get();
        if (_type == BF_MATCHER_SET && bf_set_is_anonymous(set)) {
            std::vector<const void *> elements;

            for (auto *node = set->elems.head; node; node = node->next)
                elements.push_back(node->data);

            int r = bf_matcher_new_for_anon_set(&matcher, set->key,
                                                set->n_comps, elements.data(),
                                                elements.size(), _negate);
            if (r != 0)
                throw std::runtime_error(
                    "failed to create anonymous set matcher");

            return std::unique_ptr<bf_matcher, deleter>(matcher);
        }

        if (_type == BF_MATCHER_SET && chain)
            set = bf_chain_get_set_by_name(chain, set->name);

        int r;
        if (_type == BF_MATCHER_SET)
            r = bf_matcher_new_for_named_set(&matcher, set, _negate);
        else
            r = bf_matcher_new(&matcher, _type, _op, _payload.data(),
                               _payload.size(), _negate);
        if (r != 0)
            throw std::runtime_error("failed to create bf_matcher");

        return std::unique_ptr<bf_matcher, deleter>(matcher);
    }
};

} // namespace bf
