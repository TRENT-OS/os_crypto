/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Digest.h
 *
 * @brief Crypto library implementation of Digest functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "LibDebug/Debug.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct SeosCryptoLib_Digest SeosCryptoLib_Digest;

// Exported functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_Digest_init(
    SeosCryptoLib_Digest**         self,
    const SeosCryptoApi_MemIf*     memIf,
    const SeosCryptoApi_Digest_Alg algorithm);

seos_err_t
SeosCryptoLib_Digest_free(
    SeosCryptoLib_Digest*      self,
    const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoLib_Digest_clone(
    SeosCryptoLib_Digest*       self,
    const SeosCryptoLib_Digest* source);

seos_err_t
SeosCryptoLib_Digest_process(
    SeosCryptoLib_Digest* self,
    const void*           data,
    const size_t          dataSize);

seos_err_t
SeosCryptoLib_Digest_finalize(
    SeosCryptoLib_Digest* self,
    void*                 digest,
    size_t*               digestSize);

/** @} */
