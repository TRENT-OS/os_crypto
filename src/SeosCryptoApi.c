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

// Allocate proxy object and set its API handle
#define PROXY_INIT(p, c)                                                \
    if (NULL == &(p) || NULL == (c)) {                                  \
        return SEOS_ERROR_INVALID_PARAMETER;                            \
    }                                                                   \
    if(((p) = c->memIf.malloc(sizeof(SeosCryptoApi_Proxy))) == NULL) {  \
        return SEOS_ERROR_INSUFFICIENT_SPACE;                           \
    }                                                                   \
    (p)->hCrypto = (c);
// Free proxy object with associated API context's mem IF
#define PROXY_FREE(p)                           \
    if (NULL == (p)) {                          \
        return SEOS_ERROR_INVALID_PARAMETER;    \
    }                                           \
    (p)->hCrypto->memIf.free(p);
// Call function from proxy objects API handle
#define PROXY_CALL(p, f, ...)                                                   \
    (NULL == (p)) ? SEOS_ERROR_INVALID_PARAMETER :                              \
        (NULL == (p)->hCrypto->impl.vtable->f) ? SEOS_ERROR_NOT_SUPPORTED :     \
        (p)->hCrypto->impl.vtable->f((p)->hCrypto->impl.context, __VA_ARGS__)   \
// Get object from proxy
#define PROXY_GET_OBJ(p) ((NULL == (p)) ? NULL : (p)->obj)
// Get object specific pointers to object from proxy
#define PROXY_GET_OBJ_PTR(p) ((NULL == (p)) ? NULL : &(p)->obj)
#define PROXY_GET_AGREE_PTR(p) \
    (SeosCryptoLib_Agreement**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_CIPHER_PTR(p) \
    (SeosCryptoLib_Cipher**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_DIGEST_PTR(p) \
    (SeosCryptoLib_Digest**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_KEY_PTR(p) \
    (SeosCryptoLib_Key**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_MAC_PTR(p) \
    (SeosCryptoLib_Mac**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_SIG_PTR(p) \
    (SeosCryptoLib_Signature**) PROXY_GET_OBJ_PTR(p)

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
    SeosCryptoApi_MacH*         hMac,
    const SeosCryptoApiH        self,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    seos_err_t err;

    PROXY_INIT(*hMac, self);
    if ((err = PROXY_CALL(*hMac, Mac_init, PROXY_GET_MAC_PTR(*hMac),
                          algorithm)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hMac);
    }

    return err;
}

seos_err_t
SeosCryptoApi_Mac_free(
    SeosCryptoApi_MacH hMac)
{
    seos_err_t err;

    err = PROXY_CALL(hMac, Mac_free, PROXY_GET_OBJ(hMac));
    PROXY_FREE(hMac);

    return err;
}

seos_err_t
SeosCryptoApi_Mac_start(
    SeosCryptoApi_MacH hMac,
    const void*        secret,
    const size_t       secretSize)
{
    return PROXY_CALL(hMac, Mac_start, PROXY_GET_OBJ(hMac), secret, secretSize);
}

seos_err_t
SeosCryptoApi_Mac_process(
    SeosCryptoApi_MacH hMac,
    const void*        data,
    const size_t       dataSize)
{
    return PROXY_CALL(hMac, Mac_process, PROXY_GET_OBJ(hMac), data, dataSize);
}

seos_err_t
SeosCryptoApi_Mac_finalize(
    SeosCryptoApi_MacH hMac,
    void*              mac,
    size_t*            macSize)
{
    return PROXY_CALL(hMac, Mac_finalize, PROXY_GET_OBJ(hMac), mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoApi_Digest_init(
    SeosCryptoApi_DigestH*         hDigest,
    const SeosCryptoApiH           self,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    seos_err_t err;

    PROXY_INIT(*hDigest, self);
    if ((err = PROXY_CALL(*hDigest, Digest_init, PROXY_GET_DIGEST_PTR(*hDigest),
                          algorithm)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hDigest);
    }

    return err;
}

seos_err_t
SeosCryptoApi_Digest_free(
    SeosCryptoApi_DigestH hDigest)
{
    seos_err_t err;

    err = PROXY_CALL(hDigest, Digest_free, PROXY_GET_OBJ(hDigest));
    PROXY_FREE(hDigest);

    return err;
}

seos_err_t
SeosCryptoApi_Digest_clone(
    SeosCryptoApi_DigestH       hDstDigest,
    const SeosCryptoApi_DigestH hSrcDigest)
{
    return PROXY_CALL(hDstDigest, Digest_clone, PROXY_GET_OBJ(hDstDigest),
                      PROXY_GET_OBJ(hSrcDigest));
}

seos_err_t
SeosCryptoApi_Digest_process(
    SeosCryptoApi_DigestH hDigest,
    const void*           data,
    const size_t          dataSize)
{
    return PROXY_CALL(hDigest, Digest_process, PROXY_GET_OBJ(hDigest), data,
                      dataSize);
}

seos_err_t
SeosCryptoApi_Digest_finalize(
    SeosCryptoApi_DigestH hDigest,
    void*                 digest,
    size_t*               digestSize)
{
    return PROXY_CALL(hDigest, Digest_finalize, PROXY_GET_OBJ(hDigest), digest,
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
    SeosCryptoApi_AgreementH*         hAgree,
    const SeosCryptoApiH              self,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key*          prPrvKey)
{
    seos_err_t err;

    PROXY_INIT(*hAgree, self);
    if ((err = PROXY_CALL(*hAgree, Agreement_init, PROXY_GET_AGREE_PTR(*hAgree),
                          algorithm, GET_OBJ(prPrvKey, key))) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hAgree);
    }

    return err;
}

seos_err_t
SeosCryptoApi_Agreement_free(
    SeosCryptoApi_AgreementH hAgree)
{
    seos_err_t err;

    err = PROXY_CALL(hAgree, Agreement_free, PROXY_GET_OBJ(hAgree));
    PROXY_FREE(hAgree);

    return err;
}

seos_err_t
SeosCryptoApi_Agreement_agree(
    SeosCryptoApi_AgreementH hAgree,
    const SeosCryptoApi_Key* prPubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    return PROXY_CALL(hAgree, Agreement_agree, PROXY_GET_OBJ(hAgree),
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
    SeosCryptoApi_CipherH*         hCipher,
    const SeosCryptoApiH           self,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key*       prKey,
    const void*                    iv,
    const size_t                   ivSize)
{
    seos_err_t err;

    PROXY_INIT(*hCipher, self);
    if ((err = PROXY_CALL(*hCipher, Cipher_init, PROXY_GET_CIPHER_PTR(*hCipher),
                          algorithm, GET_OBJ(prKey, key), iv, ivSize)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hCipher);
    }

    return err;
}

seos_err_t
SeosCryptoApi_Cipher_free(
    SeosCryptoApi_CipherH hCipher)
{
    seos_err_t err;

    err = PROXY_CALL(hCipher, Cipher_free, PROXY_GET_OBJ(hCipher));
    PROXY_FREE(hCipher);

    return err;
}

seos_err_t
SeosCryptoApi_Cipher_process(
    SeosCryptoApi_CipherH hCipher,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    return PROXY_CALL(hCipher, Cipher_process, PROXY_GET_OBJ(hCipher), input,
                      inputSize, output, outputSize);
}

seos_err_t
SeosCryptoApi_Cipher_start(
    SeosCryptoApi_CipherH hCipher,
    const void*           ad,
    const size_t          adSize)
{
    return PROXY_CALL(hCipher, Cipher_start, PROXY_GET_OBJ(hCipher), ad, adSize);
}

seos_err_t
SeosCryptoApi_Cipher_finalize(
    SeosCryptoApi_CipherH hCipher,
    void*                 output,
    size_t*               outputSize)
{
    return PROXY_CALL(hCipher, Cipher_finalize, PROXY_GET_OBJ(hCipher), output,
                      outputSize);
}