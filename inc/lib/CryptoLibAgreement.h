/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/CryptoLibRng.h"
#include "lib/CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibAgreement CryptoLibAgreement_t;

// Exported functions ----------------------------------------------------------

OS_Error_t
CryptoLibAgreement_init(
    CryptoLibAgreement_t**         self,
    const CryptoLibKey_t*          prvKey,
    const OS_CryptoAgreement_Alg_t algorithm,
    const OS_Crypto_Memory_t*      memory);

OS_Error_t
CryptoLibAgreement_agree(
    CryptoLibAgreement_t* self,
    const CryptoLibKey_t* pubKey,
    void*                 shared,
    size_t*               sharedSize,
    CryptoLibRng_t*       rng);

OS_Error_t
CryptoLibAgreement_free(
    CryptoLibAgreement_t*     self,
    const OS_Crypto_Memory_t* memory);