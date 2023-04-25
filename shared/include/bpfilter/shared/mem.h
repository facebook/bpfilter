/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

/**
 * @brief Set @p ptr to NULL and return its previous value.
 *
 * @param ptr Pointer to return the value of.
 */
#define TAKE_PTR(ptr)                           \
	({                                      \
		typeof(ptr) *_pptr_ = &(ptr);   \
		typeof(ptr) _ptr_ = *_pptr_;    \
		*_pptr_ = NULL;                 \
		_ptr_;                          \
	})
