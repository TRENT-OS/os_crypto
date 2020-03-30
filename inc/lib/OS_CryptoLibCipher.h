/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLibCipher.h
 *
 * @brief Crypto library implementation of Cipher functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/OS_CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct OS_CryptoLibCipher OS_CryptoLibCipher_t;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibCipher_init(
    OS_CryptoLibCipher_t**      self,
    const OS_Crypto_Memory_t*   memIf,
    const OS_CryptoCipher_Alg_t algorithm,
    const OS_CryptoLibKey_t*    key,
    const void*                 iv,
    size_t                      ivSize);

seos_err_t
OS_CryptoLibCipher_free(
    OS_CryptoLibCipher_t*     self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
OS_CryptoLibCipher_start(
    OS_CryptoLibCipher_t* self,
    const void*           input,
    const size_t          inputSize);

seos_err_t
OS_CryptoLibCipher_process(
    OS_CryptoLibCipher_t* self,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize);

seos_err_t
OS_CryptoLibCipher_finalize(
    OS_CryptoLibCipher_t* self,
    void*                 output,
    size_t*               outputSize);

/** @} */
