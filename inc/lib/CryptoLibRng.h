/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Crypto.h"

#include "lib_compiler/compiler.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibRng CryptoLibRng_t;

// Exported functions ----------------------------------------------------------

OS_Error_t
CryptoLibRng_init(
    CryptoLibRng_t**          self,
    const if_OS_Entropy_t*    entropy,
    const OS_Crypto_Memory_t* memory);

OS_Error_t
CryptoLibRng_getBytes(
    CryptoLibRng_t*           self,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize);

OS_Error_t
CryptoLibRng_reSeed(
    CryptoLibRng_t* self,
    const void*     seed,
    const size_t    seedSize);

OS_Error_t
CryptoLibRng_free(
    CryptoLibRng_t*           self,
    const OS_Crypto_Memory_t* memory);

// Get random bytes for mbedTLS wrapper
INLINE int
CryptoLibRng_getBytesMbedtls(
    void*          self,
    unsigned char* buf,
    size_t         bufSize)
{
    // Simple wrapper for mbedTLS, to allow the buffered use of the getRandomData()
    // function as is common, but also to directly pass a function to mbedTLS
    return CryptoLibRng_getBytes(self, 0, buf, bufSize) == OS_SUCCESS ? 0 : 1;
}