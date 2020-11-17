/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibRng.h"

#include "mbedtls/ctr_drbg.h"

#include "LibMacros/Check.h"

#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibRng
{
    mbedtls_ctr_drbg_context drbg;
    if_OS_Entropy_t entropy;
};

// Private Functions -----------------------------------------------------------

static int
entropyWrapper(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    CryptoLibRng_t* self = (CryptoLibRng_t*) ctx;
    size_t s;

    s = self->entropy.read(len);
    memcpy(buf, OS_Dataport_getBuf(self->entropy.dataport), s);

    // If we cannot return as many bytes as requested, produce an error
    return (s == len) ? 0 : -1;
}

// Public Functions ------------------------------------------------------------

OS_Error_t
CryptoLibRng_init(
    CryptoLibRng_t**          self,
    const if_OS_Entropy_t*    entropy,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    CryptoLibRng_t* rng;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(entropy);
    CHECK_PTR_NOT_NULL(memory);

    if ((rng = memory->calloc(1, sizeof(CryptoLibRng_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = rng;

    rng->entropy = *entropy;
    mbedtls_ctr_drbg_init(&rng->drbg);

    if (mbedtls_ctr_drbg_seed(&rng->drbg, entropyWrapper, rng, NULL, 0) != 0)
    {
        err = OS_ERROR_ABORTED;
        goto err0;
    }

    return OS_SUCCESS;

err0:
    mbedtls_ctr_drbg_free(&rng->drbg);
    memory->free(rng);

    return err;
}

OS_Error_t
CryptoLibRng_free(
    CryptoLibRng_t*           self,
    const OS_Crypto_Memory_t* memory)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(memory);

    mbedtls_ctr_drbg_free(&self->drbg);
    memory->free(self);

    return OS_SUCCESS;
}

OS_Error_t
CryptoLibRng_getBytes(
    CryptoLibRng_t*           self,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(buf);
    CHECK_VALUE_NOT_ZERO(bufSize);

    if (flags != 0)
    {
        Debug_LOG_WARNING("Flag value of %02x is being ignored; currently no "
                          "flags are supported", flags);
    }

    return (mbedtls_ctr_drbg_random(&self->drbg, buf, bufSize) != 0) ?
           OS_ERROR_ABORTED : OS_SUCCESS;
}

OS_Error_t
CryptoLibRng_reSeed(
    CryptoLibRng_t* self,
    const void*     seed,
    const size_t    seedSize)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(seed);
    CHECK_VALUE_NOT_ZERO(seedSize);

    // Update RNG state with additional seed data
    if (mbedtls_ctr_drbg_update_ret(&self->drbg, seed, seedSize) != 0)
    {
        return OS_ERROR_ABORTED;
    }

    return OS_SUCCESS;
}