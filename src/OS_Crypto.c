/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "OS_CryptoLib.h"
#include "OS_CryptoRpcClient.h"
#include "OS_CryptoRpcServer.h"
#include "OS_CryptoRouter.h"

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

    switch (cfg->mode)
    {
    case OS_Crypto_MODE_LIBRARY:
        if ((err = OS_CryptoLib_init(&ctx->impl, &cfg->mem,
                                     &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case OS_Crypto_MODE_RPC_CLIENT:
        if ((err = OS_CryptoRpcClient_init(&ctx->impl, &cfg->mem,
                                           &cfg->impl.client)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
    case OS_Crypto_MODE_ROUTER:
        if ((err = OS_CryptoRouter_init(&ctx->impl, &cfg->mem,
                                        &cfg->impl.router)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case OS_Crypto_MODE_RPC_SERVER_WITH_LIBRARY:
        if ((err = OS_CryptoLib_init(&ctx->impl, &cfg->mem,
                                     &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        if ((err = OS_CryptoRpcServer_init((OS_CryptoRpcServer_t**) &ctx->server,
                                           &ctx->impl, &cfg->mem, &cfg->server)) != SEOS_SUCCESS)
        {
            goto err1;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
        goto err0;
    }

    return SEOS_SUCCESS;

#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
err1:
    OS_CryptoLib_free(ctx->impl.context);
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
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

    switch (self->mode)
    {
    case OS_Crypto_MODE_LIBRARY:
        err = OS_CryptoLib_free(self->impl.context);
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case OS_Crypto_MODE_RPC_CLIENT:
        err = OS_CryptoRpcClient_free(self->impl.context);
        break;
    case OS_Crypto_MODE_ROUTER:
        err = OS_CryptoRouter_free(self->impl.context);
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case OS_Crypto_MODE_RPC_SERVER_WITH_LIBRARY:
        if ((err = OS_CryptoLib_free(self->impl.context)) != SEOS_SUCCESS)
        {
            return err;
        }
        err = OS_CryptoRpcServer_free(self->server);
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
    return (NULL == self) ? NULL : self->server;
}

OS_CryptoLib_Object_ptr*
OS_Crypto_getObject(
    const OS_Crypto_Object_t* proxy)
{
    return (NULL == proxy) ? NULL : proxy->obj;
}

seos_err_t
OS_Crypto_migrateObject(
    OS_Crypto_Object_t**          proxy,
    const OS_Crypto_Handle_t      self,
    const OS_CryptoLib_Object_ptr ptr)
{
    if (NULL == ptr)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PROXY_INIT(*proxy, self);
    (*proxy)->obj = ptr;

    return SEOS_SUCCESS;
}

OS_Crypto_Mode_t
OS_Crypto_getMode(
    const OS_Crypto_Handle_t self)
{
    return (NULL == self) ? OS_Crypto_MODE_NONE : self->mode;
}