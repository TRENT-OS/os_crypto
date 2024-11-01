/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "lib/CryptoLibAgreement.h"
#include "lib/CryptoLibRng.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

#include "lib_macros/Check.h"

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibAgreement
{
    union
    {
        mbedtls_dhm_context dh;
        mbedtls_ecdh_context ecdh;
    } mbedtls;
    OS_CryptoAgreement_Alg_t algorithm;
    const CryptoLibKey_t* prvKey;
};

// Private Functions -----------------------------------------------------------

static OS_Error_t
initImpl(
    CryptoLibAgreement_t**         self,
    const CryptoLibKey_t*          prvKey,
    const OS_CryptoAgreement_Alg_t algorithm,
    const OS_Crypto_Memory_t*      memory)
{
    OS_Error_t err;
    CryptoLibAgreement_t* agr;

    if ((agr = memory->calloc(1, sizeof(CryptoLibAgreement_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(agr, 0, sizeof(CryptoLibAgreement_t));
    agr->algorithm = algorithm;
    agr->prvKey    = prvKey;

    err = OS_SUCCESS;
    switch (agr->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        mbedtls_dhm_init(&agr->mbedtls.dh);
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        mbedtls_ecdh_init(&agr->mbedtls.ecdh);
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    if (err != OS_SUCCESS)
    {
        memory->free(agr);
    }

    *self = agr;

    return err;
}

static OS_Error_t
freeImpl(
    CryptoLibAgreement_t*     self,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;

    err = OS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        mbedtls_dhm_free(&self->mbedtls.dh);
        err = OS_SUCCESS;
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        mbedtls_ecdh_free(&self->mbedtls.ecdh);
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    memory->free(self);

    return err;
}

static OS_Error_t
setKeyImpl(
    CryptoLibAgreement_t* self)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        err = (CryptoLibKey_getType(self->prvKey)
               != OS_CryptoKey_TYPE_DH_PRV) ?
              OS_ERROR_INVALID_PARAMETER :
              CryptoLibKey_writeDhPrv(self->prvKey, &self->mbedtls.dh);
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        err = (CryptoLibKey_getType(self->prvKey)
               != OS_CryptoKey_TYPE_SECP256R1_PRV) ?
              OS_ERROR_INVALID_PARAMETER :
              CryptoLibKey_writeSecp256r1Prv(self->prvKey, &self->mbedtls.ecdh);
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

// This function muxes a selection with a big switch-case construct. Those
// kind of functions, when decomposed, often result in a less readable code.
// Therefore we suppress the cyclomatic complexity analysis for this function.
// metrix++: suppress std.code.complexity:cyclomatic
static OS_Error_t
agreeImpl(
    CryptoLibAgreement_t* self,
    const CryptoLibKey_t* pubKey,
    void*                 buf,
    size_t*               bufSize,
    CryptoLibRng_t*       rng)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoAgreement_ALG_DH:
        if ((CryptoLibKey_getType(pubKey) != OS_CryptoKey_TYPE_DH_PUB)
            || CryptoLibKey_writeDhPub(pubKey, &self->mbedtls.dh) != OS_SUCCESS)
        {
            err = OS_ERROR_INVALID_PARAMETER;
        }
        else if (*bufSize < mbedtls_mpi_size(&self->mbedtls.dh.P))
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
            *bufSize = mbedtls_mpi_size(&self->mbedtls.dh.P);
        }
        else
        {
            err = mbedtls_dhm_calc_secret(&self->mbedtls.dh, buf, *bufSize, bufSize,
                                          CryptoLibRng_getBytesMbedtls, rng) != 0 ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
        }
        break;
    case OS_CryptoAgreement_ALG_ECDH:
        if ((CryptoLibKey_getType(pubKey) != OS_CryptoKey_TYPE_SECP256R1_PUB)
            || CryptoLibKey_writeSecp256r1Pub(pubKey,
                                              &self->mbedtls.ecdh) != OS_SUCCESS)
        {
            err = OS_ERROR_INVALID_PARAMETER;
        }
        else if (*bufSize < mbedtls_mpi_size(&self->mbedtls.ecdh.grp.P))
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
            *bufSize = mbedtls_mpi_size(&self->mbedtls.ecdh.grp.P);
        }
        else
        {
            err = mbedtls_ecdh_calc_secret(&self->mbedtls.ecdh, bufSize, buf, *bufSize,
                                           CryptoLibRng_getBytesMbedtls, rng) != 0 ?
                  OS_ERROR_ABORTED : OS_SUCCESS;
        }
        break;
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

// Public Functions ------------------------------------------------------------

OS_Error_t
CryptoLibAgreement_init(
    CryptoLibAgreement_t**         self,
    const CryptoLibKey_t*          prvKey,
    const OS_CryptoAgreement_Alg_t algorithm,
    const OS_Crypto_Memory_t*      memory)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(prvKey);
    CHECK_PTR_NOT_NULL(memory);

    if ((err = initImpl(self, prvKey, algorithm, memory)) == OS_SUCCESS)
    {
        if ((err = setKeyImpl(*self)) != OS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibAgreement_free(
    CryptoLibAgreement_t*     self,
    const OS_Crypto_Memory_t* memory)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);

    return freeImpl(self, memory);
}

OS_Error_t
CryptoLibAgreement_agree(
    CryptoLibAgreement_t* self,
    const CryptoLibKey_t* pubKey,
    void*                 shared,
    size_t*               sharedSize,
    CryptoLibRng_t*       rng)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(pubKey);
    CHECK_PTR_NOT_NULL(shared);
    CHECK_PTR_NOT_NULL(sharedSize);
    CHECK_PTR_NOT_NULL(rng);

    return agreeImpl(self, pubKey, shared, sharedSize, rng);
}
