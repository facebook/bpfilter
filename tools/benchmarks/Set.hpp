/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

extern "C" {
    #include "core/set.h"
    #include "core/matcher.h"
}

namespace bf {

class Set
{
protected:
    struct deleter {
        void operator()(bf_set *ptr) {
            bf_set_free(&ptr);
        }
    };

    std::vector<bf_matcher_type> _key;
    size_t _key_size = 0;
    std::vector<std::vector<uint8_t>> _elements;

public:
    Set(std::vector<bf_matcher_type> key): _key{std::move(key)} {
        for (bf_matcher_type type: _key) {
            const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);
            _key_size += meta->ops[BF_MATCHER_IN].ref_payload_size;
        }
    }

    Set &operator<<(const std::vector<uint8_t>& element) {
        if (element.size() != _key_size)
            return *this;

        _elements.push_back(element);

        return *this;
    }

    [[nodiscard]] std::unique_ptr<bf_set, deleter> get() const {
        struct bf_set *set;

        int r = bf_set_new(&set, const_cast<bf_matcher_type *>(_key.data()), _key.size());
        if (r != 0)
            throw std::runtime_error("failed to create a new bf_set");

        for (const auto &element: _elements) {
            r = bf_set_add_elem(set, const_cast<void *>(reinterpret_cast<const void *>(element.data())));
            if (r != 0) {
                bf_set_free(&set);
                throw std::runtime_error("failed to add element to bf_set");
            }
        }

        return std::unique_ptr<bf_set, deleter>(set);
    }
};

}
