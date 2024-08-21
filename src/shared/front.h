/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

enum bf_front
{
    BF_FRONT_IPT,
    BF_FRONT_NFT,
    BF_FRONT_CLI,
    _BF_FRONT_MAX,
};

/**
 * @brief Get a bpfilter front type as a string.
 *
 * @param front Valid front type.
 * @return String representation of the front type.
 */
const char *bf_front_to_str(enum bf_front front);
