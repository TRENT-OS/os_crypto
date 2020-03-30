/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLibAgreement.h
 *
 * @brief Crypto library implementation of Agreement functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/OS_CryptoLibRng.h"
#include "lib/OS_CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct OS_CryptoLibAgreement OS_CryptoLibAgreement_t;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibAgreement_init(
    OS_CryptoLibAgreement_t**      self,
    const OS_Crypto_Memory_t*      memIf,
    const OS_CryptoAgreement_Alg_t algorithm,
    const OS_CryptoLibKey_t*       prvKey);

seos_err_t
OS_CryptoLibAgreement_agree(
    OS_CryptoLibAgreement_t* self,
    OS_CryptoLibRng_t*       rng,
    const OS_CryptoLibKey_t* pubKey,
    void*                    shared,
    size_t*                  sharedSize);

seos_err_t
OS_CryptoLibAgreement_free(
    OS_CryptoLibAgreement_t*  self,
    const OS_Crypto_Memory_t* memIf);

/** @} */
