// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

/**
 * @struct bf_counter
 *
 * Counters assigne to each rule.
 *
 * @var bf_counter::packets
 *  Number of packets gone through a rule.
 * @var bf_counter::bytes
 *  Number of bytes gone through a rule.
 */
struct bf_counter
{
    uint64_t packets;
    uint64_t bytes;
} bf_packed;
