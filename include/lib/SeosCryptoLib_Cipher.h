/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Cipher.h
 *
 * @brief Crypto library implementation of Cipher functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct SeosCryptoLib_Cipher SeosCryptoLib_Cipher;

// Exported functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_Cipher_init(
    SeosCryptoLib_Cipher**         self,
    const SeosCryptoApi_MemIf*     memIf,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       key,
    const void*                    iv,
    size_t                         ivSize);

seos_err_t
SeosCryptoLib_Cipher_free(
    SeosCryptoLib_Cipher*      self,
    const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoLib_Cipher_start(
    SeosCryptoLib_Cipher* self,
    const void*           input,
    const size_t          inputSize);

seos_err_t
SeosCryptoLib_Cipher_process(
    SeosCryptoLib_Cipher* self,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize);

seos_err_t
SeosCryptoLib_Cipher_finalize(
    SeosCryptoLib_Cipher* self,
    void*                 output,
    size_t*               outputSize);

/** @} */
