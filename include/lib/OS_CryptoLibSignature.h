/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLibSignature.h
 *
 * @brief Crypto library implementation of Signature functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/OS_CryptoLibRng.h"
#include "lib/OS_CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct OS_CryptoLibSignature OS_CryptoLibSignature;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibSignature_init(
    OS_CryptoLibSignature**      self,
    const OS_Crypto_Memory*      memIf,
    const OS_CryptoSignature_Alg algorithm,
    const OS_CryptoDigest_Alg    digest,
    const OS_CryptoLibKey*       prvKey,
    const OS_CryptoLibKey*       pubKey);

seos_err_t
OS_CryptoLibSignature_free(
    OS_CryptoLibSignature*  self,
    const OS_Crypto_Memory* memIf);

seos_err_t
OS_CryptoLibSignature_sign(
    OS_CryptoLibSignature* self,
    OS_CryptoLibRng*       rng,
    const void*            hash,
    const size_t           hashSize,
    void*                  signature,
    size_t*                signatureSize);

seos_err_t
OS_CryptoLibSignature_verify(
    OS_CryptoLibSignature* self,
    OS_CryptoLibRng*       rng,
    const void*            hash,
    const size_t           hashSize,
    const void*            signature,
    const size_t           signatureSize);

/** @} */