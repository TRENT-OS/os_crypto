/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoMac.h
 *
 * @brief Message authentication code (MAC) functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/md.h"

#include <stdbool.h>
#include <stddef.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoMac
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
SeosCryptoMac_init(
    SeosCryptoMac*              self,
    const SeosCryptoApi_MemIf*  memIf,
    const SeosCryptoApi_Mac_Alg algorithm);

seos_err_t
SeosCryptoMac_free(
    SeosCryptoMac*             self,
    const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoMac_start(
    SeosCryptoMac* self,
    const void*    secret,
    const size_t   secretSize);

seos_err_t
SeosCryptoMac_process(
    SeosCryptoMac* self,
    const void*    data,
    const size_t   dataSize);

seos_err_t
SeosCryptoMac_finalize(
    SeosCryptoMac* self,
    void*          mac,
    size_t*        macSize);

/** @} */
