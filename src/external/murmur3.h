//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the
// public domain. The author hereby disclaims copyright to this source
// code.
//
// Implemented by @PeterScott https://github.com/PeterScott/murmur3

#pragma once

#include <stdint.h>

void murmur3_x86_32(const void *key, int len, uint32_t seed, void *out);
void murmur3_x86_128(const void *key, int len, uint32_t seed, void *out);
void murmur3_x64_128(const void *key, int len, uint32_t seed, void *out);
