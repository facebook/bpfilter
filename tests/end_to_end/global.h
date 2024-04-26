/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _log(fd, fmt, ...) ({ fprintf(fd, fmt "\n", ##__VA_ARGS__); })
#define ok(fmt, ...) _log(stdout, "ok : " fmt, ##__VA_ARGS__)
#define err(fmt, ...) _log(stderr, "err: " fmt, ##__VA_ARGS__)
