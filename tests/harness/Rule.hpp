/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

#include "Matcher.hpp"

extern "C" {
#include <bpfilter/counter.h>
#include <bpfilter/rule.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>
}

namespace bf
{

class Rule
{
private:
    struct deleter
    {
        void operator()(bf_rule *ptr)
        {
            bf_rule_free(&ptr);
        }
    };

    bf_verdict _verdict;
    std::optional<struct bf_counter> _counters;
    uint8_t _log;
    std::vector<Matcher> _matchers;

public:
    Rule(bf_verdict verdict,
         std::optional<struct bf_counter> counters = std::nullopt,
         uint8_t log = 0, std::vector<Matcher> matchers = {}):
        _verdict {verdict},
        _counters {counters},
        _log {log},
        _matchers {std::move(matchers)}
    {}

    Rule &operator<<(Matcher &&matcher)
    {
        _matchers.push_back(matcher);

        return *this;
    }

    [[nodiscard]] std::unique_ptr<bf_rule, deleter> get() const
    {
        struct bf_rule *rule;

        int r = bf_rule_new(&rule);
        if (r != 0)
            throw std::runtime_error("failed to create bf_rule");

        rule->log = _log;
        rule->has_counters = _counters.has_value();
        rule->verdict = _verdict;

        for (const Matcher &matcher: _matchers) {
            const auto &payload = matcher.payload();
            r = bf_rule_add_matcher(rule, matcher.type(), matcher.op(),
                                    payload.data(), payload.size(),
                                    matcher.negate());
            if (r != 0) {
                bf_rule_free(&rule);
                throw std::runtime_error("failed to add bf_matcher to bf_rule");
            }
        }

        return std::unique_ptr<bf_rule, deleter>(rule);
    }
};

} // namespace bf
