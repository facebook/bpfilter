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
#include <bpfilter/matcher.h>
#include <bpfilter/set.h>
}

namespace bf
{

class Set
{
private:
    struct deleter
    {
        void operator()(bf_set *ptr)
        {
            bf_set_free(&ptr);
        }
    };

    std::shared_ptr<bf_set> _prototype;
    std::vector<std::vector<uint8_t>> _elements;

public:
    Set(std::vector<bf_matcher_type> key)
    {
        struct bf_set *set = nullptr;

        if (bf_set_new(&set, nullptr, key.data(), key.size()) != 0)
            throw std::runtime_error("failed to create a new bf_set");

        _prototype = std::shared_ptr<bf_set>(set, deleter());
    }

    Set &operator<<(const std::vector<uint8_t> &element)
    {
        if (element.size() != _prototype->elem_size) {
            throw std::invalid_argument(
                "number of elements in the vector should match the number of components in the set key");
        }

        _elements.push_back(element);

        return *this;
    }

    [[nodiscard]] std::unique_ptr<bf_set, deleter> get() const
    {
        struct bf_set *set = nullptr;

        int r = bf_set_new_from_copy(&set, _prototype.get());
        if (r != 0)
            throw std::runtime_error("failed to create a new bf_set");

        for (const auto &element: _elements) {
            r = bf_set_add_elem(
                set, const_cast<void *>(
                         reinterpret_cast<const void *>(element.data())));
            if (r != 0) {
                bf_set_free(&set);
                throw std::runtime_error("failed to add element to bf_set");
            }
        }

        return std::unique_ptr<bf_set, deleter>(set);
    }

    [[nodiscard]] std::shared_ptr<const bf_set> ref() const
    {
        return _prototype;
    }
};

} // namespace bf
