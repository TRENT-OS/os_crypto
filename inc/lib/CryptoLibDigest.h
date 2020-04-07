/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file CryptoLibDigest.h
 *
 * @brief Crypto library implementation of Digest functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "LibDebug/Debug.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibDigest CryptoLibDigest_t;

// Exported functions ----------------------------------------------------------

seos_err_t
CryptoLibDigest_init(
    CryptoLibDigest_t**         self,
    const OS_CryptoDigest_Alg_t algorithm,
    const OS_Crypto_Memory_t*   memIf);

seos_err_t
CryptoLibDigest_free(
    CryptoLibDigest_t*        self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
CryptoLibDigest_clone(
    CryptoLibDigest_t*       self,
    const CryptoLibDigest_t* source);

seos_err_t
CryptoLibDigest_process(
    CryptoLibDigest_t* self,
    const void*        data,
    const size_t       dataSize);

seos_err_t
CryptoLibDigest_finalize(
    CryptoLibDigest_t* self,
    void*              digest,
    size_t*            digestSize);

/** @} */
