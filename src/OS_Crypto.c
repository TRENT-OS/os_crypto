/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLib.h"
#include "rpc/CryptoLibClient.h"
#include "rpc/CryptoLibServer.h"

// Public functions ------------------------------------------------------------

seos_err_t
OS_Crypto_init(
    OS_Crypto_Handle_t*       self,
    const OS_Crypto_Config_t* cfg)
{
    seos_err_t err;
    OS_Crypto_t* ctx;

    if (NULL == self || NULL == cfg || NULL == cfg->mem.malloc
        || NULL == cfg->mem.free)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((ctx = cfg->mem.malloc(sizeof(OS_Crypto_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = ctx;

    ctx->mode  = cfg->mode;
    ctx->memIf = cfg->mem;

    // We always need a library instance; unless we want to force the API to
    // delegate everything to the server
    if (cfg->mode != OS_Crypto_MODE_CLIENT_ONLY)
    {
        if ((err = CryptoLib_init(&ctx->library, &cfg->mem,
                                  &cfg->library)) != SEOS_SUCCESS)
        {
            goto err0;
        }
    }

    switch (cfg->mode)
    {
    case  OS_Crypto_MODE_LIBRARY_ONLY:
        // This is already set up.
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case OS_Crypto_MODE_CLIENT_ONLY:
    case OS_Crypto_MODE_CLIENT:
        if ((err = CryptoLibClient_init(&ctx->rpc.client, &cfg->mem,
                                        &cfg->rpc.client)) != SEOS_SUCCESS)
        {
            goto err1;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case OS_Crypto_MODE_SERVER:
        if ((err = CryptoLibServer_init(&ctx->rpc.server, &ctx->library, &cfg->mem,
                                        &cfg->rpc.server)) != SEOS_SUCCESS)
        {
            goto err1;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    if (cfg->mode != OS_Crypto_MODE_CLIENT_ONLY)
    {
        CryptoLib_free(ctx->library.context);
    }
err0:
    ctx->memIf.free(ctx);

    return err;
}

seos_err_t
OS_Crypto_free(
    OS_Crypto_Handle_t self)
{
    seos_err_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (self->mode != OS_Crypto_MODE_CLIENT_ONLY)
    {
        if ((err = CryptoLib_free(self->library.context)) != SEOS_SUCCESS)
        {
            return err;
        }
    }

    switch (self->mode)
    {
    case OS_Crypto_MODE_LIBRARY_ONLY:
        // Nothing more to do.
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case OS_Crypto_MODE_CLIENT_ONLY:
    case OS_Crypto_MODE_CLIENT:
        err = CryptoLibClient_free(self->rpc.client.context);
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case OS_Crypto_MODE_SERVER:
        err = CryptoLibServer_free(self->rpc.server);
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

void*
OS_Crypto_getServer(
    const OS_Crypto_Handle_t self)
{
    return (NULL == self || self->mode != OS_Crypto_MODE_SERVER) ?
           NULL : self->rpc.server;
}

CryptoLib_Object_ptr*
OS_Crypto_getObject(
    const OS_Crypto_Object_t* proxy)
{
    return (NULL == proxy) ? NULL : proxy->obj;
}

seos_err_t
OS_Crypto_migrateObject(
    OS_Crypto_Object_t**       proxy,
    const OS_Crypto_Handle_t   self,
    const CryptoLib_Object_ptr ptr)
{
    if (NULL == ptr)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    // When we migrate a CryptoLib object, it is expected that this comes from a
    // remote instance. So the only meaningful way to use it through the client.
    PROXY_INIT(*proxy, self, true);
    (*proxy)->obj = ptr;

    return SEOS_SUCCESS;
}

OS_Crypto_Mode_t
OS_Crypto_getMode(
    const OS_Crypto_Handle_t self)
{
    return (NULL == self) ? OS_Crypto_MODE_NONE : self->mode;
}