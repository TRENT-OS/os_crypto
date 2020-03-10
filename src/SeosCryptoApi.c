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

// ------------------------------- Init/Free -----------------------------------

seos_err_t
SeosCryptoApi_init(
    SeosCryptoApi*              self,
    const SeosCryptoApi_Config* cfg)
{
    seos_err_t err;

    if (NULL == self || NULL == cfg || NULL == cfg->mem.malloc
        || NULL == cfg->mem.free)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));
    self->mode = cfg->mode;

    switch (cfg->mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        if ((err = SeosCryptoLib_init(&self->impl, &cfg->mem,
                                      &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case SeosCryptoApi_Mode_RPC_CLIENT:
        if ((err = SeosCryptoRpc_Client_init(&self->impl, &cfg->mem,
                                             &cfg->impl.client)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
    case SeosCryptoApi_Mode_ROUTER:
        if ((err = SeosCryptoRouter_init(&self->impl, &cfg->mem,
                                         &cfg->impl.router)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        break;
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY:
        if ((err = SeosCryptoLib_init(&self->impl, &cfg->mem,
                                      &cfg->impl.lib)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        if ((err = SeosCryptoRpc_Server_init((SeosCryptoRpc_Server**) &self->server,
                                             &self->impl, &cfg->mem, &cfg->server)) != SEOS_SUCCESS)
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
    SeosCryptoLib_free(self->impl.context);
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
err0:

    return err;
}

seos_err_t
SeosCryptoApi_free(
    SeosCryptoApi* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        return SeosCryptoLib_free(self->impl.context);
#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)
    case SeosCryptoApi_Mode_RPC_CLIENT:
        return SeosCryptoRpc_Client_free(self->impl.context);
    case SeosCryptoApi_Mode_ROUTER:
        return SeosCryptoRouter_free(self->impl.context);
#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */
#if defined(SEOS_CRYPTO_WITH_RPC_SERVER)
    case SeosCryptoApi_Mode_RPC_SERVER_WITH_LIBRARY:
    {
        seos_err_t err;
        if ((err = SeosCryptoLib_free(self->impl.context)) != SEOS_SUCCESS)
        {
            return err;
        }
        return SeosCryptoRpc_Server_free(self->server);
    }
#endif /* SEOS_CRYPTO_WITH_RPC_SERVER */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoApi_Rng_getBytes(
    SeosCryptoApi*               self,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize)
{
    return CALL_IMPL(self, Rng_getBytes, flags, buf, bufSize);
}

seos_err_t
SeosCryptoApi_Rng_reseed(
    SeosCryptoApi* self,
    const void*    seed,
    const size_t   seedSize)
{
    return CALL_IMPL(self, Rng_reseed, seed, seedSize);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
SeosCryptoApi_Mac_init(
    SeosCryptoApi*              api,
    SeosCryptoApi_Mac*          prMac,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    INIT_PROXY(prMac, api);
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
    SeosCryptoApi*                 api,
    SeosCryptoApi_Digest*          prDigest,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    INIT_PROXY(prDigest, api);
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
    SeosCryptoApi*                    api,
    SeosCryptoApi_Signature*          prSig,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoApi_Key*          prPrvKey,
    const SeosCryptoApi_Key*          prPubKey)
{
    INIT_PROXY(prSig, api);
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
    SeosCryptoApi*                    api,
    SeosCryptoApi_Agreement*          prAgr,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key*          prPrvKey)
{
    INIT_PROXY(prAgr, api);
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
    SeosCryptoApi*                api,
    SeosCryptoApi_Key*            prKey,
    const SeosCryptoApi_Key_Spec* spec)
{
    INIT_PROXY(prKey, api);
    return CALL_IMPL(prKey, Key_generate, &prKey->key, spec);
}

seos_err_t
SeosCryptoApi_Key_import(
    SeosCryptoApi*                api,
    SeosCryptoApi_Key*            prKey,
    const SeosCryptoApi_Key_Data* keyData)
{
    INIT_PROXY(prKey, api);
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
    SeosCryptoApi_Key*                prKey,
    const SeosCryptoApi_Key_RemotePtr ptr)
{
    if (NULL == ptr)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    INIT_PROXY(prKey, api);
    prKey->key = ptr;

    return SEOS_SUCCESS;
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoApi_Cipher_init(
    SeosCryptoApi*                 api,
    SeosCryptoApi_Cipher*          prCipher,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key*       prKey,
    const void*                    iv,
    const size_t                   ivSize)
{
    INIT_PROXY(prCipher, api);
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