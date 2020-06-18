/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibMac.h"

#include "mbedtls/md.h"

#include "compiler.h"

#include <string.h>
#include <stdbool.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibMac
{
    union
    {
        mbedtls_md_context_t md;
    } mbedtls;
    OS_CryptoMac_Alg_t algorithm;
    const CryptoLibKey_t* key;
    bool processed;
};

// Private Functions -----------------------------------------------------------

static OS_Error_t
initImpl(
    CryptoLibMac_t**          self,
    const CryptoLibKey_t*     key,
    const OS_CryptoMac_Alg_t  algorithm,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;
    CryptoLibMac_t* mac;
    mbedtls_md_type_t type;

    if ((mac = memory->calloc(1, sizeof(CryptoLibMac_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(mac, 0, sizeof(CryptoLibMac_t));
    mac->algorithm = algorithm;
    mac->key       = key;
    mac->processed = false;

    switch (mac->algorithm)
    {
    case OS_CryptoMac_ALG_HMAC_MD5:
        type = MBEDTLS_MD_MD5;
        break;
    case OS_CryptoMac_ALG_HMAC_SHA256:
        type = MBEDTLS_MD_SHA256;
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
        goto err0;
    }

    mbedtls_md_init(&mac->mbedtls.md);
    if (mbedtls_md_setup(&mac->mbedtls.md, mbedtls_md_info_from_type(type), 1))
    {
        err = OS_ERROR_ABORTED;
        goto err1;
    }

    *self = mac;

    return OS_SUCCESS;

err1:
    mbedtls_md_free(&mac->mbedtls.md);
err0:
    memory->free(mac);

    return err;
}

static OS_Error_t
freeImpl(
    CryptoLibMac_t*           self,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;

    err = OS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoMac_ALG_HMAC_MD5:
    case OS_CryptoMac_ALG_HMAC_SHA256:
        mbedtls_md_free(&self->mbedtls.md);
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    memory->free(self);

    return err;
}

static OS_Error_t
startImpl(
    CryptoLibMac_t* self)
{
    OS_CryptoKey_Mac_t* macKey;
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoMac_ALG_HMAC_MD5:
    case OS_CryptoMac_ALG_HMAC_SHA256:
        if (CryptoLibKey_getType(self->key) != OS_CryptoKey_TYPE_MAC ||
            (macKey = CryptoLibKey_getMac(self->key)) == NULL)
        {
            return OS_ERROR_INVALID_PARAMETER;
        }
        err = mbedtls_md_hmac_starts(&self->mbedtls.md, macKey->bytes, macKey->len) ?
              OS_ERROR_ABORTED : OS_SUCCESS;
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static OS_Error_t
processImpl(
    CryptoLibMac_t* self,
    const void*     data,
    const size_t    dataSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoMac_ALG_HMAC_MD5:
    case OS_CryptoMac_ALG_HMAC_SHA256:
        err = mbedtls_md_hmac_update(&self->mbedtls.md, data, dataSize) ?
              OS_ERROR_ABORTED : OS_SUCCESS;
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static OS_Error_t
finalizeImpl(
    CryptoLibMac_t* self,
    void*           mac,
    size_t*         macSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    err = OS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoMac_ALG_HMAC_MD5:
        if (*macSize < OS_CryptoMac_SIZE_HMAC_MD5)
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
        }
        *macSize = OS_CryptoMac_SIZE_HMAC_MD5;
        break;
    case OS_CryptoMac_ALG_HMAC_SHA256:
        if (*macSize < OS_CryptoMac_SIZE_HMAC_SHA256)
        {
            err = OS_ERROR_BUFFER_TOO_SMALL;
        }
        *macSize = OS_CryptoMac_SIZE_HMAC_SHA256;
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    if (OS_SUCCESS == err)
    {
        // We do not need to reset anything here, as the internal state machine
        // will force the user to call start() again first, which re-sets the
        // hmac and the underlying digest context.
        err = mbedtls_md_hmac_finish(&self->mbedtls.md, mac) ?
              OS_ERROR_ABORTED : OS_SUCCESS;
    }

    return err;
}

// Public Functions ------------------------------------------------------------

OS_Error_t
CryptoLibMac_init(
    CryptoLibMac_t**          self,
    const CryptoLibKey_t*     key,
    const OS_CryptoMac_Alg_t  algorithm,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;

    if (NULL == memory || NULL == key || NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((err = initImpl(self, key, algorithm, memory)) == OS_SUCCESS)
    {
        if ((err = startImpl(*self)) != OS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibMac_free(
    CryptoLibMac_t*           self,
    const OS_Crypto_Memory_t* memory)
{
    if (NULL == memory || NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memory);
}

OS_Error_t
CryptoLibMac_process(
    CryptoLibMac_t* self,
    const void*     data,
    const size_t    dataSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    if (NULL == self || NULL == data || 0 == dataSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = processImpl(self, data, dataSize);
    self->processed |= (OS_SUCCESS == err);

    return err;
}

OS_Error_t
CryptoLibMac_finalize(
    CryptoLibMac_t* self,
    void*           mac,
    size_t*         macSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    if (NULL == self || NULL == mac || NULL == macSize || 0 == *macSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = !self->processed ?
          OS_ERROR_ABORTED : finalizeImpl(self, mac, macSize);

    // Finalize also resets the underlying algorithms, so that we can re-use the
    // MAC object again
    if (err == OS_SUCCESS)
    {
        self->processed = false;
        err = startImpl(self);
    }

    return err;
}