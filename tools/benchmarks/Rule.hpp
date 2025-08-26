/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <memory>
#include <stdexcept>
#include <vector>
#include <bitset>
#include "core/Matcher.hpp"

extern "C" {
    #include "core/rule.h"
    #include "core/runtime.h"
    #include "core/verdict.h"
}

namespace bf {

using RuleLogBitset = std::bitset<_BF_PKTHDR_MAX>;

class Rule
{
private:
    struct deleter {
        void operator()(bf_rule *ptr) {
            bf_rule_free(&ptr);
        }
    };

    bf_verdict _verdict;
    bool _counters;
    RuleLogBitset _log;
    std::vector<Matcher> _matchers;

public:
    Rule(bf_verdict verdict, bool counters = false, RuleLogBitset log = {}, std::vector<Matcher> matchers = {}):
        _verdict{verdict}, _counters{counters}, _log{log}, _matchers{std::move(matchers)} {}

    Rule &operator<<(Matcher &&matcher) {
        _matchers.push_back(matcher);

        return *this;
    }

    [[nodiscard]] std::unique_ptr<bf_rule, deleter> get() const {
        struct bf_rule *rule;

        int r = bf_rule_new(&rule);
        if (r != 0)
            throw std::runtime_error("failed to create bf_rule");

        rule->log = static_cast<uint8_t>(_log.to_ulong());
        rule->counters = _counters;
        rule->verdict = _verdict;

        for (const Matcher &matcher: _matchers) {
            const auto &payload = matcher.payload();
            r = bf_rule_add_matcher(rule, matcher.type(), matcher.op(), payload.data(), payload.size());
            if (r != 0) {
                bf_rule_free(&rule);
                throw std::runtime_error("failed to add bf_matcher to bf_rule");
            }
        }

        return std::unique_ptr<bf_rule, deleter>(rule);
    }
};

}
