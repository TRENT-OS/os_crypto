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

// -------------------------- defines/types/variables --------------------------

// A proxy object could be NULL, if so, just pass NULL
#define GET_OBJ(p, o) ((p) == NULL ? NULL : (p)->o)

// We call a function from a proxy object's API. Make sure that the API call
// is actually implemented.
#define CALL_IMPL(p, f, ...)                                        \
    (NULL == p) ? SEOS_ERROR_INVALID_PARAMETER :                    \
        (NULL == p->impl.vtable->f) ? SEOS_ERROR_NOT_SUPPORTED :    \
        p->impl.vtable->f(p->impl.context, __VA_ARGS__)             \

// Initialize a proxy object from existing API pointer
#define INIT_PROXY(p, c) {                      \
    if (NULL == p || NULL == c) {               \
        return SEOS_ERROR_INVALID_PARAMETER;    \
    }                                           \
    memset(p, 0, sizeof(*p));                   \
    p->impl = c->impl;                          \
}

struct SeosCryptoApi
{
    SeosCryptoApi_Mode mode;
    SeosCryptoApi_Impl impl;
    SeosCryptoApi_MemIf memIf;
    void* server;
};

// ------------------------------- Init/Free -----------------------------------

seos_err_t
SeosCryptoApi_init(
    SeosCryptoApiH*             self,
    const SeosCryptoApi_Config* cfg)
{
    seos_err_t err;
    SeosCryptoApi* ctx;

    if (NULL == self || NULL == cfg || NULL == cfg->mem.malloc
        || NULL == cfg->mem.free)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((ctx = cfg->mem.malloc(sizeof(SeosCryptoApi))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = ctx;

    ctx->mode  = cfg->mode;
    ctx->memIf = cfg->mem;

    switch (cfg->mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        if ((err = SeosCryptoLib_init(&ctx->impl, &cfg->mem,
                                      &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case SeosCryptoApi_Mode_RPC_CLIENT:
        if ((err = SeosCryptoRpc_Client_init(&ctx->impl, &cfg->mem,
                                             &cfg->impl.client)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
    case SeosCryptoApi_Mode_ROUTER:
        if ((err = SeosCryptoRouter_init(&ctx->impl, &cfg->mem,
                                         &cfg->impl.router)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY:
        if ((err = SeosCryptoLib_init(&ctx->impl, &cfg->mem,
                                      &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        if ((err = SeosCryptoRpc_Server_init((SeosCryptoRpc_Server**) &ctx->server,
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
    SeosCryptoLib_free(ctx->impl.context);
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
err0:
    ctx->memIf.free(ctx);

    return err;
}

seos_err_t
SeosCryptoApi_free(
    SeosCryptoApiH self)
{
    seos_err_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        err = SeosCryptoLib_free(self->impl.context);
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case SeosCryptoApi_Mode_RPC_CLIENT:
        err = SeosCryptoRpc_Client_free(self->impl.context);
        break;
    case SeosCryptoApi_Mode_ROUTER:
        err = SeosCryptoRouter_free(self->impl.context);
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY:
        if ((err = SeosCryptoLib_free(self->impl.context)) != SEOS_SUCCESS)
        {
            return err;
        }
        err = SeosCryptoRpc_Server_free(self->server);
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

void*
SeosCryptoApi_getServer(
    const SeosCryptoApiH self)
{
    return (NULL == self) ? NULL : self->server;
}

SeosCryptoLib_Object*
SeosCryptoApi_getObject(
    const SeosCryptoApi_Proxy* proxy)
{
    return (NULL == proxy) ? NULL : proxy->obj;
}

seos_err_t
SeosCryptoApi_migrateObject(
    SeosCryptoApi_Proxy**      proxy,
    const SeosCryptoApiH       self,
    const SeosCryptoLib_Object ptr)
{
    if (NULL == ptr)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PROXY_INIT(*proxy, self);
    (*proxy)->obj = ptr;

    return SEOS_SUCCESS;
}

SeosCryptoApi_Mode
SeosCryptoApi_getMode(
    const SeosCryptoApiH self)
{
    return (NULL == self) ? SeosCryptoApi_Mode_NONE : self->mode;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_Rng_getBytes(
    SeosCryptoApiH               self,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize)
{
    return CALL_IMPL(self, Rng_getBytes, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_Rng_reseed(
    SeosCryptoApiH self,
    const void*    seed,
    const size_t   seedSize)
{
    return CALL_IMPL(self, Rng_reseed, seed, seedSize);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoApi_Mac_init(
    SeosCryptoApiH              self,
    SeosCryptoApi_Mac*          prMac,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    INIT_PROXY(prMac, self);
    return CALL_IMPL(prMac, Mac_init, &prMac->mac, algorithm);
}

seos_err_t
SeosCryptoApi_Mac_free(
    SeosCryptoApi_Mac* prMac)
{
    return CALL_IMPL(prMac, Mac_free, GET_OBJ(prMac, mac));
}

seos_err_t
SeosCryptoApi_Mac_start(
    SeosCryptoApi_Mac* prMac,
    const void*        secret,
    const size_t       secretSize)
{
    return CALL_IMPL(prMac, Mac_start, GET_OBJ(prMac, mac), secret, secretSize);
}

seos_err_t
SeosCryptoApi_Mac_process(
    SeosCryptoApi_Mac* prMac,
    const void*        data,
    const size_t       dataSize)
{
    return CALL_IMPL(prMac, Mac_process, GET_OBJ(prMac, mac), data, dataSize);
}

seos_err_t
SeosCryptoApi_Mac_finalize(
    SeosCryptoApi_Mac* prMac,
    void*              mac,
    size_t*            macSize)
{
    return CALL_IMPL(prMac, Mac_finalize, GET_OBJ(prMac, mac), mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_Digest_init(
    SeosCryptoApiH                 self,
    SeosCryptoApi_Digest*          prDigest,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    INIT_PROXY(prDigest, self);
    return CALL_IMPL(prDigest, Digest_init, &prDigest->digest, algorithm);
}

seos_err_t
SeosCryptoApi_Digest_free(
    SeosCryptoApi_Digest* prDigest)
{
    return CALL_IMPL(prDigest, Digest_free, GET_OBJ(prDigest, digest));
}

seos_err_t
SeosCryptoApi_Digest_clone(
    SeosCryptoApi_Digest*       prDigest,
    const SeosCryptoApi_Digest* prSrcDigest)
{
    return CALL_IMPL(prDigest, Digest_clone, GET_OBJ(prDigest, digest),
                     GET_OBJ(prSrcDigest, digest));
}

seos_err_t
SeosCryptoApi_Digest_process(
    SeosCryptoApi_Digest* prDigest,
    const void*           data,
    const size_t          dataSize)
{
    return CALL_IMPL(prDigest, Digest_process, GET_OBJ(prDigest, digest), data,
                     dataSize);
}

seos_err_t
SeosCryptoApi_Digest_finalize(
    SeosCryptoApi_Digest* prDigest,
    void*                 digest,
    size_t*               digestSize)
{
    return CALL_IMPL(prDigest, Digest_finalize, GET_OBJ(prDigest, digest), digest,
                     digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoApi_Signature_init(
    SeosCryptoApiH                    self,
    SeosCryptoApi_Signature*          prSig,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoApi_Key*          prPrvKey,
    const SeosCryptoApi_Key*          prPubKey)
{
    INIT_PROXY(prSig, self);
    return CALL_IMPL(prSig, Signature_init, &prSig->signature, algorithm, digest,
                     GET_OBJ(prPrvKey, key), GET_OBJ(prPubKey, key));
}

seos_err_t
SeosCryptoApi_Signature_free(
    SeosCryptoApi_Signature* prSig)
{
    return CALL_IMPL(prSig, Signature_free, GET_OBJ(prSig, signature));
}

seos_err_t
SeosCryptoApi_Signature_sign(
    SeosCryptoApi_Signature* prSig,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    return CALL_IMPL(prSig, Signature_sign, GET_OBJ(prSig, signature), hash,
                     hashSize, signature, signatureSize);
}

seos_err_t
SeosCryptoApi_Signature_verify(
    SeosCryptoApi_Signature* prSig,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    return CALL_IMPL(prSig, Signature_verify, GET_OBJ(prSig, signature), hash,
                     hashSize, signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoApi_Agreement_init(
    SeosCryptoApiH                    self,
    SeosCryptoApi_Agreement*          prAgr,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key*          prPrvKey)
{
    INIT_PROXY(prAgr, self);
    return CALL_IMPL(prAgr, Agreement_init, &prAgr->agreement, algorithm,
                     GET_OBJ(prPrvKey, key));
}

seos_err_t
SeosCryptoApi_Agreement_free(
    SeosCryptoApi_Agreement* prAgr)
{
    return CALL_IMPL(prAgr, Agreement_free, GET_OBJ(prAgr, agreement));
}

seos_err_t
SeosCryptoApi_Agreement_agree(
    SeosCryptoApi_Agreement* prAgr,
    const SeosCryptoApi_Key* prPubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    return CALL_IMPL(prAgr, Agreement_agree, GET_OBJ(prAgr, agreement),
                     GET_OBJ(prPubKey, key), shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCryptoApi_Key_generate(
    SeosCryptoApiH                self,
    SeosCryptoApi_Key*            prKey,
    const SeosCryptoApi_Key_Spec* spec)
{
    INIT_PROXY(prKey, self);
    return CALL_IMPL(prKey, Key_generate, &prKey->key, spec);
}

seos_err_t
SeosCryptoApi_Key_import(
    SeosCryptoApiH                self,
    SeosCryptoApi_Key*            prKey,
    const SeosCryptoApi_Key_Data* keyData)
{
    INIT_PROXY(prKey, self);
    return CALL_IMPL(prKey, Key_import, &prKey->key, keyData);
}

seos_err_t
SeosCryptoApi_Key_makePublic(
    SeosCryptoApi_Key*               prKey,
    const SeosCryptoApi_Key*         prPrvKey,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    INIT_PROXY(prKey, prPrvKey);
    return CALL_IMPL(prKey, Key_makePublic, &prKey->key, GET_OBJ(prPrvKey, key),
                     attribs);
}

seos_err_t
SeosCryptoApi_Key_export(
    const SeosCryptoApi_Key* prKey,
    SeosCryptoApi_Key_Data*  keyData)
{
    return CALL_IMPL(prKey, Key_export, GET_OBJ(prKey, key), keyData);
}

seos_err_t
SeosCryptoApi_Key_getParams(
    const SeosCryptoApi_Key* prKey,
    void*                    keyParams,
    size_t*                  paramSize)
{
    return CALL_IMPL(prKey, Key_getParams, GET_OBJ(prKey, key), keyParams,
                     paramSize);
}

seos_err_t
SeosCryptoApi_Key_getAttribs(
    const SeosCryptoApi_Key*   prKey,
    SeosCryptoApi_Key_Attribs* attribs)
{
    return CALL_IMPL(prKey, Key_getAttribs, GET_OBJ(prKey, key), attribs);
}

seos_err_t
SeosCryptoApi_Key_free(
    SeosCryptoApi_Key* prKey)
{
    return CALL_IMPL(prKey, Key_free, GET_OBJ(prKey, key));
}

seos_err_t
SeosCryptoApi_Key_loadParams(
    SeosCryptoApiH                self,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    return CALL_IMPL(self, Key_loadParams, name, keyParams, paramSize);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_Cipher_init(
    SeosCryptoApiH                 self,
    SeosCryptoApi_Cipher*          prCipher,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key*       prKey,
    const void*                    iv,
    const size_t                   ivSize)
{
    INIT_PROXY(prCipher, self);
    return CALL_IMPL(prCipher, Cipher_init, &prCipher->cipher, algorithm,
                     GET_OBJ(prKey, key), iv, ivSize);
}

seos_err_t
SeosCryptoApi_Cipher_free(
    SeosCryptoApi_Cipher* prCipher)
{
    return CALL_IMPL(prCipher, Cipher_free, GET_OBJ(prCipher, cipher));
}

seos_err_t
SeosCryptoApi_Cipher_process(
    SeosCryptoApi_Cipher* prCipher,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    return CALL_IMPL(prCipher, Cipher_process, GET_OBJ(prCipher, cipher), input,
                     inputSize, output, outputSize);
}

seos_err_t
SeosCryptoApi_Cipher_start(
    SeosCryptoApi_Cipher* prCipher,
    const void*           ad,
    const size_t          adSize)
{
    return CALL_IMPL(prCipher, Cipher_start, GET_OBJ(prCipher, cipher), ad, adSize);
}

seos_err_t
SeosCryptoApi_Cipher_finalize(
    SeosCryptoApi_Cipher* prCipher,
    void*                 output,
    size_t*               outputSize)
{
    return CALL_IMPL(prCipher, Cipher_finalize, GET_OBJ(prCipher, cipher), output,
                     outputSize);
}