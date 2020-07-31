/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLib.h"
#include "rpc/CryptoLibClient.h"
#include "rpc/CryptoLibServer.h"

#include <stdlib.h>

// Public functions ------------------------------------------------------------

OS_Error_t
OS_Crypto_init(
    OS_Crypto_Handle_t*       self,
    const OS_Crypto_Config_t* cfg)
{
    OS_Error_t err;
    OS_Crypto_t* ctx;

    if (NULL == self || NULL == cfg)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if ((NULL == cfg->memory.calloc && NULL != cfg->memory.free) ||
        (NULL != cfg->memory.calloc && NULL == cfg->memory.free))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // If both are NULL, use calloc/freem from stdin.h, otherwise use the ones
    // provided in the config.
    if ((NULL == cfg->memory.calloc && NULL == cfg->memory.free))
    {
        if ((ctx = calloc(1, sizeof(OS_Crypto_t))) == NULL)
        {
            return OS_ERROR_INSUFFICIENT_SPACE;
        }
    }
    else if ((ctx = cfg->memory.calloc(1, sizeof(OS_Crypto_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = ctx;

    ctx->mode = cfg->mode;
    ctx->memory.calloc = (cfg->memory.calloc == NULL) ?
                         calloc : cfg->memory.calloc;
    ctx->memory.free = (cfg->memory.free == NULL) ?
                       free : cfg->memory.free;

    // We always need a library instance; unless we want to force the API to
    // delegate everything to the server
    if (cfg->mode != OS_Crypto_MODE_CLIENT_ONLY)
    {
        if ((err = CryptoLib_init(&ctx->library,
                                  &ctx->memory,
                                  &cfg->library.entropy)) != OS_SUCCESS)
        {
            goto err0;
        }
    }

    switch (cfg->mode)
    {
    case  OS_Crypto_MODE_LIBRARY_ONLY:
        // This is already set up.
        break;
#if defined(OS_CRYPTO_WITH_RPC_CLIENT)
    case OS_Crypto_MODE_CLIENT_ONLY:
    case OS_Crypto_MODE_CLIENT:
        if ((err = CryptoLibClient_init(&ctx->rpc.client,
                                        &ctx->memory,
                                        &cfg->dataport)) != OS_SUCCESS)
        {
            goto err1;
        }
        break;
#endif /* OS_CRYPTO_WITH_RPC_CLIENT */
#if defined(OS_CRYPTO_WITH_RPC_SERVER)
    case OS_Crypto_MODE_SERVER:
        if ((err = CryptoLibServer_init(&ctx->rpc.server,
                                        &ctx->library,
                                        &ctx->memory,
                                        &cfg->dataport)) != OS_SUCCESS)
        {
            goto err1;
        }
        break;
#endif /* OS_CRYPTO_WITH_RPC_SERVER */
    default:
        err = OS_ERROR_NOT_SUPPORTED;
        goto err1;
    }

    return OS_SUCCESS;

err1:
    if (cfg->mode != OS_Crypto_MODE_CLIENT_ONLY)
    {
        CryptoLib_free(ctx->library.context);
    }
err0:
    ctx->memory.free(ctx);

    return err;
}

OS_Error_t
OS_Crypto_free(
    OS_Crypto_Handle_t self)
{
    OS_Error_t err;

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (self->mode != OS_Crypto_MODE_CLIENT_ONLY)
    {
        if ((err = CryptoLib_free(self->library.context)) != OS_SUCCESS)
        {
            return err;
        }
    }

    switch (self->mode)
    {
    case OS_Crypto_MODE_LIBRARY_ONLY:
        // Nothing more to do.
        break;
#if defined(OS_CRYPTO_WITH_RPC_CLIENT)
    case OS_Crypto_MODE_CLIENT_ONLY:
    case OS_Crypto_MODE_CLIENT:
        err = CryptoLibClient_free(self->rpc.client.context);
        break;
#endif /* OS_CRYPTO_WITH_RPC_CLIENT */
#if defined(OS_CRYPTO_WITH_RPC_SERVER)
    case OS_Crypto_MODE_SERVER:
        err = CryptoLibServer_free(self->rpc.server);
        break;
#endif /* OS_CRYPTO_WITH_RPC_SERVER */
    default:
        err = OS_ERROR_NOT_SUPPORTED;
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
OS_Crypto_getLibObject(
    const OS_Crypto_Object_t* proxy)
{
    return (NULL == proxy) ? NULL : proxy->obj;
}

OS_Error_t
OS_Crypto_migrateLibObject(
    OS_Crypto_Object_t**       proxy,
    const OS_Crypto_Handle_t   self,
    const CryptoLib_Object_ptr ptr,
    const bool                 local)
{
    /*
     * Generally speaking, crypto library objects can be in our local address
     * space or in a remote address space (e.g., the CryptoServer). As a result,
     * the proxy objects needs to know the appropriate vtable/context.
     */

    if (NULL == self || NULL == ptr)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (!local && self->mode == OS_Crypto_MODE_LIBRARY_ONLY)
    {
        // If it is a remote object, then we can only access it through the
        // RPC client, so "library only" will not work.
        return OS_ERROR_INVALID_STATE;
    }

    PROXY_INIT(*proxy, self, !local);
    (*proxy)->obj = ptr;

    return OS_SUCCESS;
}

OS_Crypto_Mode_t
OS_Crypto_getMode(
    const OS_Crypto_Handle_t self)
{
    return (NULL == self) ? OS_Crypto_MODE_NONE : self->mode;
}