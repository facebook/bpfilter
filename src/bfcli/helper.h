
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/list.h"

struct bfc_ruleset;

int bfc_parse_file(const char *file, struct bfc_ruleset *ruleset);
int bfc_parse_str(const char *str, struct bfc_ruleset *ruleset);
