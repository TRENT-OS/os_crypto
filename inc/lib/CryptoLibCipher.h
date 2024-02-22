/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibCipher CryptoLibCipher_t;

// Exported functions ----------------------------------------------------------

OS_Error_t
CryptoLibCipher_init(
    CryptoLibCipher_t**         self,
    const CryptoLibKey_t*       key,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    size_t                      ivSize,
    const OS_Crypto_Memory_t*   memory);

OS_Error_t
CryptoLibCipher_free(
    CryptoLibCipher_t*        self,
    const OS_Crypto_Memory_t* memory);

OS_Error_t
CryptoLibCipher_start(
    CryptoLibCipher_t* self,
    const void*        input,
    const size_t       inputSize);

OS_Error_t
CryptoLibCipher_process(
    CryptoLibCipher_t* self,
    const void*        input,
    const size_t       inputSize,
    void*              output,
    size_t*            outputSize);

OS_Error_t
CryptoLibCipher_finalize(
    CryptoLibCipher_t* self,
    void*              output,
    size_t*            outputSize);