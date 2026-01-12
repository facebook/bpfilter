
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bfc_opts;

int bfc_chain_set(const struct bfc_opts *opts);
int bfc_chain_get(const struct bfc_opts *opts);
int bfc_chain_logs(const struct bfc_opts *opts);
int bfc_chain_load(const struct bfc_opts *opts);
int bfc_chain_attach(const struct bfc_opts *opts);
int bfc_chain_update(const struct bfc_opts *opts);
int bfc_chain_update_set(const struct bfc_opts *opts);
int bfc_chain_flush(const struct bfc_opts *opts);
