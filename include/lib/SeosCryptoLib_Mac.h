/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Mac.h
 *
 * @brief Crypto library implementation of Message Authentication Code (MAC) functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/md.h"

#include <stdbool.h>
#include <stddef.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoLib_Mac
{
    union
    {
        mbedtls_md_context_t md;
    }
    mbedtls;
    SeosCryptoApi_Mac_Alg algorithm;
    bool started;
    bool processed;
};

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_Mac_init(
    SeosCryptoLib_Mac*          self,
    const SeosCryptoApi_MemIf*  memIf,
    const SeosCryptoApi_Mac_Alg algorithm);

seos_err_t
SeosCryptoLib_Mac_free(
    SeosCryptoLib_Mac*         self,
    const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoLib_Mac_start(
    SeosCryptoLib_Mac* self,
    const void*        secret,
    const size_t       secretSize);

seos_err_t
SeosCryptoLib_Mac_process(
    SeosCryptoLib_Mac* self,
    const void*        data,
    const size_t       dataSize);

seos_err_t
SeosCryptoLib_Mac_finalize(
    SeosCryptoLib_Mac* self,
    void*              mac,
    size_t*            macSize);

/** @} */
