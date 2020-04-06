/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file CryptoLibSignature_t.h
 *
 * @brief Crypto library implementation of Signature functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/CryptoLibRng.h"
#include "lib/CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibSignature CryptoLibSignature_t;

// Exported functions ----------------------------------------------------------

seos_err_t
CryptoLibSignature_init(
    CryptoLibSignature_t**         self,
    const OS_Crypto_Memory_t*      memIf,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest,
    const CryptoLibKey_t*          prvKey,
    const CryptoLibKey_t*          pubKey);

seos_err_t
CryptoLibSignature_free(
    CryptoLibSignature_t*     self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
CryptoLibSignature_sign(
    CryptoLibSignature_t* self,
    CryptoLibRng_t*       rng,
    const void*           hash,
    const size_t          hashSize,
    void*                 signature,
    size_t*               signatureSize);

seos_err_t
CryptoLibSignature_verify(
    CryptoLibSignature_t* self,
    CryptoLibRng_t*       rng,
    const void*           hash,
    const size_t          hashSize,
    const void*           signature,
    const size_t          signatureSize);

/** @} */