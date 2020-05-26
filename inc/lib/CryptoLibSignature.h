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

OS_Error_t
CryptoLibSignature_init(
    CryptoLibSignature_t**         self,
    const CryptoLibKey_t*          prvKey,
    const CryptoLibKey_t*          pubKey,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest,
    const OS_Crypto_Memory_t*      memory);

OS_Error_t
CryptoLibSignature_free(
    CryptoLibSignature_t*     self,
    const OS_Crypto_Memory_t* memory);

OS_Error_t
CryptoLibSignature_sign(
    CryptoLibSignature_t* self,
    const void*           hash,
    const size_t          hashSize,
    void*                 signature,
    size_t*               signatureSize,
    CryptoLibRng_t*       rng);

OS_Error_t
CryptoLibSignature_verify(
    CryptoLibSignature_t* self,
    const void*           hash,
    const size_t          hashSize,
    const void*           signature,
    const size_t          signatureSize,
    CryptoLibRng_t*       rng);

/** @} */