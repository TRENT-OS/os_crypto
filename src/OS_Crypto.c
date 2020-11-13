/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#include "lib/CryptoLib.h"
#include "rpc/CryptoLibClient.h"

#include "LibMacros/Check.h"

#include <stdlib.h>

// Private functions -----------------------------------------------------------
static inline OS_Error_t
initImpl(
    OS_Crypto_t* ctx,
    const OS_Crypto_Config_t* cfg)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    // We always need a library instance; unless we want to force the API to
    // delegate everything to the server
    if (cfg->mode != OS_Crypto_MODE_CLIENT)
    {
        if ((err = CryptoLib_init(&ctx->library,
                                  &ctx->memory,
                                  &cfg->entropy)) != OS_SUCCESS)
        {
            return err;
        }
    }

    switch (cfg->mode)
    {
    case  OS_Crypto_MODE_LIBRARY:
        // This is already set up.
        break;
    case OS_Crypto_MODE_CLIENT:
    case OS_Crypto_MODE_KEY_SWITCH:
        if ((err = CryptoLibClient_init(&ctx->client,
                                        &ctx->memory,
                                        &cfg->rpc)) != OS_SUCCESS)
        {
            goto err;
        }
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
        goto err;
    }

    return OS_SUCCESS;

err:
    if (cfg->mode != OS_Crypto_MODE_CLIENT)
    {
        CryptoLib_free(ctx->library.context);
    }
    return err;
}

static inline OS_Error_t
isInitParametersOk(
    OS_Crypto_Handle_t*       self,
    const OS_Crypto_Config_t* cfg)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(cfg);

    // either no memory handler is set or both handlers must be set
    if ((NULL == cfg->memory.calloc && NULL != cfg->memory.free) ||
        (NULL != cfg->memory.calloc && NULL == cfg->memory.free))
    {
        Debug_LOG_ERROR("Cannot have only one of calloc/free set and the "
                        "other NULL");
        return OS_ERROR_INVALID_PARAMETER;
    }

    return OS_SUCCESS;
}

// Public functions ------------------------------------------------------------

OS_Error_t
OS_Crypto_init(
    OS_Crypto_Handle_t*       self,
    const OS_Crypto_Config_t* cfg)
{
    OS_Error_t err;
    OS_Crypto_t* ctx;

    if ((err = isInitParametersOk(self, cfg)) != OS_SUCCESS)
    {
        return err;
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

    err = initImpl(ctx, cfg);
    if (err != OS_SUCCESS)
    {
        goto err;
    }

    return OS_SUCCESS;
err:
    ctx->memory.free(ctx);
    return err;
}

OS_Error_t
OS_Crypto_free(
    OS_Crypto_Handle_t self)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);

    if (self->mode != OS_Crypto_MODE_CLIENT)
    {
        if ((err = CryptoLib_free(self->library.context)) != OS_SUCCESS)
        {
            return err;
        }
    }

    switch (self->mode)
    {
    case OS_Crypto_MODE_LIBRARY:
        // Nothing more to do.
        break;
    case OS_Crypto_MODE_CLIENT:
    case OS_Crypto_MODE_KEY_SWITCH:
        err = CryptoLibClient_free(self->client.context);
        break;
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

void*
OS_Crypto_getProxyPtr(
    const OS_Crypto_Object_t* proxy)
{
    return (NULL == proxy) ? NULL : proxy->obj;
}

OS_Error_t
OS_Crypto_createProxy(
    OS_Crypto_Object_t**       proxy,
    const OS_Crypto_Handle_t   self,
    const void*                ptr,
    const bool                 local)
{
    /*
     * Generally speaking, crypto library objects can be in our local address
     * space or in a remote address space (e.g., the CryptoServer). As a result,
     * the proxy objects needs to know the appropriate vtable/context.
     */

    CHECK_PTR_NOT_NULL(proxy);
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(ptr);

    if (!local && self->mode == OS_Crypto_MODE_LIBRARY)
    {
        Debug_LOG_ERROR("Cannot create a remote proxy object, when library "
                        "instance is configured in OS_Crypto_MODE_LIBRARY "
                        "mode");
        return OS_ERROR_INVALID_STATE;
    }

    PROXY_INIT(*proxy, self, !local);
    (*proxy)->obj = (void*)ptr;

    return OS_SUCCESS;
}

OS_Crypto_Mode_t
OS_Crypto_getMode(
    const OS_Crypto_Handle_t self)
{
    return (NULL == self) ? OS_Crypto_MODE_NONE : self->mode;
}
