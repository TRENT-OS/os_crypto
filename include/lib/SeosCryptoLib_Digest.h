/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoLib_Digest.h
 *
 * @brief Digest functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

#include "LibDebug/Debug.h"

#include <stdbool.h>
#include <stddef.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoLib_Digest
{
    union
    {
        mbedtls_md5_context md5;
        mbedtls_sha256_context sha256;
    }
    mbedtls;
    SeosCryptoApi_Digest_Alg algorithm;
    bool processed;
};

// Internal functions ----------------------------------------------------------

// Make sure these hold, otherwise stuff will break!
Debug_STATIC_ASSERT((int)SeosCryptoApi_Digest_ALG_NONE     ==
                    (int)MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT((int)SeosCryptoApi_Digest_ALG_MD5      ==
                    (int)MBEDTLS_MD_MD5);
Debug_STATIC_ASSERT((int)SeosCryptoApi_Digest_ALG_SHA256   ==
                    (int)MBEDTLS_MD_SHA256);

seos_err_t
SeosCryptoLib_Digest_init(
    SeosCryptoLib_Digest*          self,
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
