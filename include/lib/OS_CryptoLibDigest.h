/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLibDigest.h
 *
 * @brief Crypto library implementation of Digest functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "LibDebug/Debug.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct OS_CryptoLibDigest OS_CryptoLibDigest;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibDigest_init(
    OS_CryptoLibDigest**      self,
    const OS_Crypto_Memory*   memIf,
    const OS_CryptoDigest_Alg algorithm);

seos_err_t
OS_CryptoLibDigest_free(
    OS_CryptoLibDigest*     self,
    const OS_Crypto_Memory* memIf);

seos_err_t
OS_CryptoLibDigest_clone(
    OS_CryptoLibDigest*       self,
    const OS_CryptoLibDigest* source);

seos_err_t
OS_CryptoLibDigest_process(
    OS_CryptoLibDigest* self,
    const void*         data,
    const size_t        dataSize);

seos_err_t
OS_CryptoLibDigest_finalize(
    OS_CryptoLibDigest* self,
    void*               digest,
    size_t*             digestSize);

/** @} */
