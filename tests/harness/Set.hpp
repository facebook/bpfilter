/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <memory>
#include <optional>
#include <stdexcept>
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

public:
    Set(std::vector<bf_matcher_type> key, std::optional<std::string> name = {})
    {
        struct bf_set *set = nullptr;

        if (bf_set_new(&set, name ? name->c_str() : nullptr, key.data(),
                       key.size()) != 0)
            throw std::runtime_error("failed to create a new bf_set");

        _prototype = std::shared_ptr<bf_set>(set, deleter());
    }

    Set &operator<<(const std::vector<uint8_t> &element)
    {
        if (element.size() != _prototype->elem_size) {
            throw std::invalid_argument(
                "number of elements in the vector should match the number of components in the set key");
        }

        if (bf_set_add_elem(_prototype.get(), element.data()) != 0)
            throw std::runtime_error("failed to add element to bf_set");

        return *this;
    }

    [[nodiscard]] std::unique_ptr<bf_set, deleter> get() const
    {
        struct bf_set *set = nullptr;

        int r = bf_set_new_from_copy(&set, _prototype.get());
        if (r != 0)
            throw std::runtime_error("failed to create a new bf_set");

        return std::unique_ptr<bf_set, deleter>(set);
    }

    [[nodiscard]] std::shared_ptr<const bf_set> ref() const
    {
        return _prototype;
    }
};

} // namespace bf
