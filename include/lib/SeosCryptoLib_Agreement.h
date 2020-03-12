/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Agreement.h
 *
 * @brief Crypto library implementation of Agreement functions
 *
 */

#pragma once

#include "SeosCryptoLib.h"
#include "lib/SeosCryptoLib_Rng.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct SeosCryptoLib_Agreement SeosCryptoLib_Agreement;

// Exported functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_Agreement_init(
    SeosCryptoLib_Agreement**         self,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          privateKey);

seos_err_t
SeosCryptoLib_Agreement_agree(
    SeosCryptoLib_Agreement* self,
    SeosCryptoLib_Rng*       rng,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize);

seos_err_t
SeosCryptoLib_Agreement_free(
    SeosCryptoLib_Agreement*   self,
    const SeosCryptoApi_MemIf* memIf);

/** @} */
