/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file CryptoLibCipher.h
 *
 * @brief Crypto library implementation of Cipher functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibCipher CryptoLibCipher_t;

// Exported functions ----------------------------------------------------------

seos_err_t
CryptoLibCipher_init(
    CryptoLibCipher_t**         self,
    const CryptoLibKey_t*       key,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    size_t                      ivSize,
    const OS_Crypto_Memory_t*   memIf);

seos_err_t
CryptoLibCipher_free(
    CryptoLibCipher_t*        self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
CryptoLibCipher_start(
    CryptoLibCipher_t* self,
    const void*        input,
    const size_t       inputSize);

seos_err_t
CryptoLibCipher_process(
    CryptoLibCipher_t* self,
    const void*        input,
    const size_t       inputSize,
    void*              output,
    size_t*            outputSize);

seos_err_t
CryptoLibCipher_finalize(
    CryptoLibCipher_t* self,
    void*              output,
    size_t*            outputSize);

/** @} */
