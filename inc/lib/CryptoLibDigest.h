/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Crypto.h"

#include "lib_debug/Debug.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibDigest CryptoLibDigest_t;

// Exported functions ----------------------------------------------------------

OS_Error_t
CryptoLibDigest_init(
    CryptoLibDigest_t**         self,
    const OS_CryptoDigest_Alg_t algorithm,
    const OS_Crypto_Memory_t*   memory);

OS_Error_t
CryptoLibDigest_clone(
    CryptoLibDigest_t**       self,
    const CryptoLibDigest_t*  source,
    const OS_Crypto_Memory_t* memory);

OS_Error_t
CryptoLibDigest_free(
    CryptoLibDigest_t*        self,
    const OS_Crypto_Memory_t* memory);

OS_Error_t
CryptoLibDigest_process(
    CryptoLibDigest_t* self,
    const void*        data,
    const size_t       dataSize);

OS_Error_t
CryptoLibDigest_finalize(
    CryptoLibDigest_t* self,
    void*              digest,
    size_t*            digestSize);