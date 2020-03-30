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

typedef struct OS_CryptoLibDigest OS_CryptoLibDigest_t;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibDigest_init(
    OS_CryptoLibDigest_t**      self,
    const OS_Crypto_Memory_t*   memIf,
    const OS_CryptoDigest_Alg_t algorithm);

seos_err_t
OS_CryptoLibDigest_free(
    OS_CryptoLibDigest_t*     self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
OS_CryptoLibDigest_clone(
    OS_CryptoLibDigest_t*       self,
    const OS_CryptoLibDigest_t* source);

seos_err_t
OS_CryptoLibDigest_process(
    OS_CryptoLibDigest_t* self,
    const void*           data,
    const size_t          dataSize);

seos_err_t
OS_CryptoLibDigest_finalize(
    OS_CryptoLibDigest_t* self,
    void*                 digest,
    size_t*               digestSize);

/** @} */
