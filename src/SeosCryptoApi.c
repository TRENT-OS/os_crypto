/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "SeosCryptoLib.h"
#include "SeosCryptoRpc_Client.h"
#include "SeosCryptoRpc_Server.h"
#include "SeosCryptoRouter.h"

#include "SeosCryptoVtable.h"

#include <string.h>

// A wrapped object could be NULL, if so, just pass NULL
#define UNWRAP(w, o) ((w) == NULL ? NULL : (w)->o)

// We call a function from a wrapped object's API. Make sure that the API call
// is actually implemented.
#define CALL_IMPL(w, f, ...)                                 \
    (NULL == w) ? SEOS_ERROR_INVALID_PARAMETER :             \
    (NULL == w->impl.vtable->f) ? SEOS_ERROR_NOT_SUPPORTED : \
    w->impl.vtable->f(w->impl.context, __VA_ARGS__)          \

// Initialize a wrapped object from existing API pointer
#define INIT_WRAPPER(w, c) {                        \
        if (NULL == w || NULL == c) {               \
            return SEOS_ERROR_INVALID_PARAMETER;    \
        }                                           \
        memset(w, 0, sizeof(*w));                   \
        w->impl = c->impl;                          \
}

// ------------------------------- Init/Free -----------------------------------

seos_err_t
SeosCryptoApi_init(
    SeosCryptoApi*              ctx,
    const SeosCryptoApi_Config* cfg)
{
    seos_err_t err;

    if (NULL == ctx || NULL == cfg || NULL == cfg->mem.malloc
        || NULL == cfg->mem.free)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->mode = cfg->mode;

    switch (cfg->mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        if ((ctx->impl.context = cfg->mem.malloc(sizeof(SeosCryptoLib))) == NULL)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        if ((err = SeosCryptoLib_init(ctx->impl.context, &ctx->impl.vtable, &cfg->mem,
                                      &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case SeosCryptoApi_Mode_RPC_CLIENT:
        if ((ctx->impl.context = cfg->mem.malloc(sizeof(SeosCryptoRpc_Client))) == NULL)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        if ((err = SeosCryptoRpc_Client_init(ctx->impl.context, &ctx->impl.vtable,
                                             &cfg->impl.client)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
    case SeosCryptoApi_Mode_ROUTER:
        if ((ctx->impl.context = cfg->mem.malloc(sizeof(SeosCryptoRouter))) == NULL)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        if ((err = SeosCryptoRouter_init(ctx->impl.context, &ctx->impl.vtable,
                                         &cfg->mem, &cfg->impl.router)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY:
        if ((ctx->impl.context = cfg->mem.malloc(sizeof(SeosCryptoLib))) == NULL)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        if ((err = SeosCryptoLib_init(ctx->impl.context, &ctx->impl.vtable, &cfg->mem,
                                      &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        if ((ctx->server.context = cfg->mem.malloc(sizeof(SeosCryptoRpc_Server))) ==
            NULL)
        {
            err = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err0;
        }
        if ((err = SeosCryptoRpc_Server_init(ctx->server.context, &ctx->impl,
                                             &cfg->server)) != SEOS_SUCCESS)
        {
            goto err1;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;

#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
err1:
    free(ctx->server.context);
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
err0:
    free(ctx->impl.context);

    return err;
}

seos_err_t
SeosCryptoApi_free(
    SeosCryptoApi* ctx)
{
    seos_err_t err;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (ctx->mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        err = SeosCryptoLib_free(ctx->impl.context);
        free(ctx->impl.context);
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case SeosCryptoApi_Mode_RPC_CLIENT:
        err = SeosCryptoRpc_Client_free(ctx->impl.context);
        free(ctx->impl.context);
        break;
    case SeosCryptoApi_Mode_ROUTER:
        err = SeosCryptoRouter_free(ctx->impl.context);
        free(ctx->impl.context);
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY:
        SeosCryptoLib_free(ctx->impl.context);
        free(ctx->impl.context);
        err = SeosCryptoRpc_Server_free(ctx->server.context);
        free(ctx->server.context);
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }
    return err;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_Rng_getBytes(
    SeosCryptoApi*               ctx,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize)
{
    return CALL_IMPL(ctx, Rng_getBytes, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_Rng_reseed(
    SeosCryptoApi* ctx,
    const void*    seed,
    const size_t   seedSize)
{
    return CALL_IMPL(ctx, Rng_reseed, seed, seedSize);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoApi_Mac_init(
    SeosCryptoApi*              api,
    SeosCryptoApi_Mac*          wrap,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    INIT_WRAPPER(wrap, api);
    return CALL_IMPL(wrap, Mac_init, &wrap->mac, algorithm);
}

seos_err_t
SeosCryptoApi_Mac_free(
    SeosCryptoApi_Mac* wrap)
{
    return CALL_IMPL(wrap, Mac_free, wrap->mac);
}

seos_err_t
SeosCryptoApi_Mac_start(
    SeosCryptoApi_Mac* wrap,
    const void*        secret,
    const size_t       secretSize)
{
    return CALL_IMPL(wrap, Mac_start, wrap->mac, secret, secretSize);
}

seos_err_t
SeosCryptoApi_Mac_process(
    SeosCryptoApi_Mac* wrap,
    const void*        data,
    const size_t       dataSize)
{
    return CALL_IMPL(wrap, Mac_process, wrap->mac, data, dataSize);
}

seos_err_t
SeosCryptoApi_Mac_finalize(
    SeosCryptoApi_Mac* wrap,
    void*              mac,
    size_t*            macSize)
{
    return CALL_IMPL(wrap, Mac_finalize, wrap->mac, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_Digest_init(
    SeosCryptoApi*                 api,
    SeosCryptoApi_Digest*          wrap,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    INIT_WRAPPER(wrap, api);
    return CALL_IMPL(wrap, Digest_init, &wrap->digest, algorithm);
}

seos_err_t
SeosCryptoApi_Digest_free(
    SeosCryptoApi_Digest* wrap)
{
    return CALL_IMPL(wrap, Digest_free, wrap->digest);
}

seos_err_t
SeosCryptoApi_Digest_clone(
    SeosCryptoApi_Digest*       wrap,
    const SeosCryptoApi_Digest* srcWrap)
{
    return CALL_IMPL(wrap, Digest_clone, wrap->digest, UNWRAP(srcWrap, digest));
}

seos_err_t
SeosCryptoApi_Digest_process(
    SeosCryptoApi_Digest* wrap,
    const void*           data,
    const size_t          dataSize)
{
    return CALL_IMPL(wrap, Digest_process, wrap->digest, data, dataSize);
}

seos_err_t
SeosCryptoApi_Digest_finalize(
    SeosCryptoApi_Digest* wrap,
    void*                 digest,
    size_t*               digestSize)
{
    return CALL_IMPL(wrap, Digest_finalize, wrap->digest, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoApi_Signature_init(
    SeosCryptoApi*                    api,
    SeosCryptoApi_Signature*          wrap,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoApi_Key*          prvKey,
    const SeosCryptoApi_Key*          pubKey)
{
    INIT_WRAPPER(wrap, api);
    return CALL_IMPL(wrap, Signature_init, &wrap->signature, algorithm, digest,
                     UNWRAP(prvKey, key), UNWRAP(pubKey, key));
}

seos_err_t
SeosCryptoApi_Signature_free(
    SeosCryptoApi_Signature* wrap)
{
    return CALL_IMPL(wrap, Signature_free, wrap->signature);
}

seos_err_t
SeosCryptoApi_Signature_sign(
    SeosCryptoApi_Signature* wrap,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    return CALL_IMPL(wrap, Signature_sign, wrap->signature, hash, hashSize,
                     signature, signatureSize);
}

seos_err_t
SeosCryptoApi_Signature_verify(
    SeosCryptoApi_Signature* wrap,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    return CALL_IMPL(wrap, Signature_verify, wrap->signature, hash, hashSize,
                     signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoApi_Agreement_init(
    SeosCryptoApi*                    api,
    SeosCryptoApi_Agreement*          wrap,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key*          prvKey)
{
    INIT_WRAPPER(wrap, api);
    return CALL_IMPL(wrap, Agreement_init, &wrap->agreement, algorithm,
                     UNWRAP(prvKey, key));
}

seos_err_t
SeosCryptoApi_Agreement_free(
    SeosCryptoApi_Agreement* wrap)
{
    return CALL_IMPL(wrap, Agreement_free, wrap->agreement);
}

seos_err_t
SeosCryptoApi_Agreement_agree(
    SeosCryptoApi_Agreement* wrap,
    const SeosCryptoApi_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    return CALL_IMPL(wrap, Agreement_agree, wrap->agreement, UNWRAP(pubKey, key),
                     shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoApi_Key_generate(
    SeosCryptoApi*                api,
    SeosCryptoApi_Key*            wrap,
    const SeosCryptoApi_Key_Spec* spec)
{
    INIT_WRAPPER(wrap, api);
    return CALL_IMPL(wrap, Key_generate, &wrap->key, spec);
}

seos_err_t
SeosCryptoApi_Key_import(
    SeosCryptoApi*                api,
    SeosCryptoApi_Key*            wrap,
    const SeosCryptoApi_Key_Data* keyData)
{
    INIT_WRAPPER(wrap, api);
    return CALL_IMPL(wrap, Key_import, &wrap->key, keyData);
}

seos_err_t
SeosCryptoApi_Key_makePublic(
    SeosCryptoApi_Key*               wrap,
    const SeosCryptoApi_Key*         prvKey,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    INIT_WRAPPER(wrap, prvKey);
    return CALL_IMPL(wrap, Key_makePublic, &wrap->key, UNWRAP(prvKey, key),
                     attribs);
}

seos_err_t
SeosCryptoApi_Key_export(
    const SeosCryptoApi_Key* wrap,
    SeosCryptoApi_Key_Data*  keyData)
{
    return CALL_IMPL(wrap, Key_export, wrap->key, keyData);
}

seos_err_t
SeosCryptoApi_Key_getParams(
    const SeosCryptoApi_Key* wrap,
    void*                    keyParams,
    size_t*                  paramSize)
{
    return CALL_IMPL(wrap, Key_getParams, wrap->key, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_Key_getAttribs(
    const SeosCryptoApi_Key*   wrap,
    SeosCryptoApi_Key_Attribs* attribs)
{
    return CALL_IMPL(wrap, Key_getAttribs, wrap->key, attribs);
}

seos_err_t
SeosCryptoApi_Key_free(
    SeosCryptoApi_Key* wrap)
{
    return CALL_IMPL(wrap, Key_free, wrap->key);
}

seos_err_t
SeosCryptoApi_Key_loadParams(
    SeosCryptoApi*                api,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    return CALL_IMPL(api, Key_loadParams, name, keyParams, paramSize);
}

seos_err_t
SeosCryptoApi_Key_migrate(
    SeosCryptoApi*                    api,
    SeosCryptoApi_Key*                wrap,
    const SeosCryptoApi_Key_RemotePtr ptr)
{
    if (NULL == ptr)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    INIT_WRAPPER(wrap, api);
    wrap->key = ptr;

    return SEOS_SUCCESS;
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_Cipher_init(
    SeosCryptoApi*                 api,
    SeosCryptoApi_Cipher*          wrap,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key*       symKey,
    const void*                    iv,
    const size_t                   ivSize)
{
    INIT_WRAPPER(wrap, api);
    return CALL_IMPL(wrap, Cipher_init, &wrap->cipher, algorithm, UNWRAP(symKey,
                     key), iv, ivSize);
}

seos_err_t
SeosCryptoApi_Cipher_free(
    SeosCryptoApi_Cipher* wrap)
{
    return CALL_IMPL(wrap, Cipher_free, wrap->cipher);
}

seos_err_t
SeosCryptoApi_Cipher_process(
    SeosCryptoApi_Cipher* wrap,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    return CALL_IMPL(wrap, Cipher_process, wrap->cipher, input, inputSize, output,
                     outputSize);
}

seos_err_t
SeosCryptoApi_Cipher_start(
    SeosCryptoApi_Cipher* wrap,
    const void*           ad,
    const size_t          adSize)
{
    return CALL_IMPL(wrap, Cipher_start, wrap->cipher, ad, adSize);
}

seos_err_t
SeosCryptoApi_Cipher_finalize(
    SeosCryptoApi_Cipher* wrap,
    void*                 output,
    size_t*               outputSize)
{
    return CALL_IMPL(wrap, Cipher_finalize, wrap->cipher, output, outputSize);
}