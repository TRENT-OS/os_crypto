/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_CryptoImpl.h"
#include "OS_CryptoLib.h"
#include "OS_CryptoRpcClient.h"
#include "OS_CryptoRpcServer.h"
#include "OS_CryptoRouter.h"

#include <string.h>

// -------------------------- defines/types/variables --------------------------

// Call function from self pointer
#define CALL(s, f, ...)                                         \
    (NULL == (s)) ? SEOS_ERROR_INVALID_PARAMETER :              \
    (NULL == (s)->impl.vtable->f) ? SEOS_ERROR_NOT_SUPPORTED :  \
    (s)->impl.vtable->f((s)->impl.context, __VA_ARGS__)         \

// Allocate proxy object and set its API handle to self pointer
#define PROXY_INIT(p, s)                                            \
    if (NULL == &(p) || NULL == (s)) {                              \
        return SEOS_ERROR_INVALID_PARAMETER;                        \
    }                                                               \
    if(((p) = s->memIf.malloc(sizeof(OS_Crypto_Object))) == NULL) { \
        return SEOS_ERROR_INSUFFICIENT_SPACE;                       \
    }                                                               \
    (p)->hCrypto = (s);

// Free proxy object with associated API context's mem IF
#define PROXY_FREE(p)                           \
    if (NULL == (p)) {                          \
        return SEOS_ERROR_INVALID_PARAMETER;    \
    }                                           \
    (p)->hCrypto->memIf.free(p);

// Call function from proxy objects API handle
#define PROXY_CALL(p, f, ...)                                               \
    (NULL == (p)) ? SEOS_ERROR_INVALID_PARAMETER :                          \
    (NULL == (p)->hCrypto->impl.vtable->f) ? SEOS_ERROR_NOT_SUPPORTED :     \
    (p)->hCrypto->impl.vtable->f((p)->hCrypto->impl.context, __VA_ARGS__)   \

// Get object from proxy
#define PROXY_GET_OBJ(p) ((NULL == (p)) ? NULL : (p)->obj)

// Get object specific pointers to object from proxy
#define PROXY_GET_OBJ_PTR(p) ((NULL == (p)) ? NULL : &(p)->obj)
#define PROXY_GET_AGREE_PTR(p) \
    (OS_CryptoLibAgreement**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_CIPHER_PTR(p) \
    (OS_CryptoLibCipher**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_DIGEST_PTR(p) \
    (OS_CryptoLibDigest**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_KEY_PTR(p) \
    (OS_CryptoLibKey**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_MAC_PTR(p) \
    (OS_CryptoLibMac**) PROXY_GET_OBJ_PTR(p)
#define PROXY_GET_SIG_PTR(p) \
    (OS_CryptoLibSignature**) PROXY_GET_OBJ_PTR(p)

struct OS_Crypto
{
    OS_Crypto_Mode mode;
    OS_CryptoImpl impl;
    OS_Crypto_Memory memIf;
    void* server;
};

struct OS_Crypto_Object
{
    OS_Crypto* hCrypto;
    OS_CryptoLib_Object obj;
};

// ------------------------------- Init/Free -----------------------------------

seos_err_t
OS_Crypto_init(
    OS_CryptoH*             self,
    const OS_Crypto_Config* cfg)
{
    seos_err_t err;
    OS_Crypto* ctx;

    if (NULL == self || NULL == cfg || NULL == cfg->mem.malloc
        || NULL == cfg->mem.free)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((ctx = cfg->mem.malloc(sizeof(OS_Crypto))) == NULL)
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
        if ((err = OS_CryptoRpcServer_init((OS_CryptoRpcServer**) &ctx->server,
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
    OS_CryptoH self)
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
    const OS_CryptoH self)
{
    return (NULL == self) ? NULL : self->server;
}

OS_CryptoLib_Object*
OS_Crypto_getObject(
    const OS_Crypto_Object* proxy)
{
    return (NULL == proxy) ? NULL : proxy->obj;
}

seos_err_t
OS_Crypto_migrateObject(
    OS_Crypto_Object**        proxy,
    const OS_CryptoH          self,
    const OS_CryptoLib_Object ptr)
{
    if (NULL == ptr)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PROXY_INIT(*proxy, self);
    (*proxy)->obj = ptr;

    return SEOS_SUCCESS;
}

OS_Crypto_Mode
OS_Crypto_getMode(
    const OS_CryptoH self)
{
    return (NULL == self) ? OS_Crypto_MODE_NONE : self->mode;
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
OS_CryptoRng_getBytes(
    OS_CryptoH              self,
    const OS_CryptoRng_Flag flags,
    void*                   buf,
    const size_t            bufSize)
{
    return CALL(self, Rng_getBytes, flags, buf, bufSize);
}

seos_err_t
OS_CryptoRng_reseed(
    OS_CryptoH   self,
    const void*  seed,
    const size_t seedSize)
{
    return CALL(self, Rng_reseed, seed, seedSize);
}

// ------------------------------- MAC API -------------------------------------

seos_err_t
OS_CryptoMac_init(
    OS_CryptoMacH*         hMac,
    const OS_CryptoH       self,
    const OS_CryptoMac_Alg algorithm)
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
OS_CryptoMac_free(
    OS_CryptoMacH hMac)
{
    seos_err_t err;

    err = PROXY_CALL(hMac, Mac_free, PROXY_GET_OBJ(hMac));
    PROXY_FREE(hMac);

    return err;
}

seos_err_t
OS_CryptoMac_start(
    OS_CryptoMacH hMac,
    const void*   secret,
    const size_t  secretSize)
{
    return PROXY_CALL(hMac, Mac_start, PROXY_GET_OBJ(hMac), secret, secretSize);
}

seos_err_t
OS_CryptoMac_process(
    OS_CryptoMacH hMac,
    const void*   data,
    const size_t  dataSize)
{
    return PROXY_CALL(hMac, Mac_process, PROXY_GET_OBJ(hMac), data, dataSize);
}

seos_err_t
OS_CryptoMac_finalize(
    OS_CryptoMacH hMac,
    void*         mac,
    size_t*       macSize)
{
    return PROXY_CALL(hMac, Mac_finalize, PROXY_GET_OBJ(hMac), mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
OS_CryptoDigest_init(
    OS_CryptoDigestH*         hDigest,
    const OS_CryptoH          self,
    const OS_CryptoDigest_Alg algorithm)
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
OS_CryptoDigest_free(
    OS_CryptoDigestH hDigest)
{
    seos_err_t err;

    err = PROXY_CALL(hDigest, Digest_free, PROXY_GET_OBJ(hDigest));
    PROXY_FREE(hDigest);

    return err;
}

seos_err_t
OS_CryptoDigest_clone(
    OS_CryptoDigestH       hDstDigest,
    const OS_CryptoDigestH hSrcDigest)
{
    return PROXY_CALL(hDstDigest, Digest_clone, PROXY_GET_OBJ(hDstDigest),
                      PROXY_GET_OBJ(hSrcDigest));
}

seos_err_t
OS_CryptoDigest_process(
    OS_CryptoDigestH hDigest,
    const void*      data,
    const size_t     dataSize)
{
    return PROXY_CALL(hDigest, Digest_process, PROXY_GET_OBJ(hDigest), data,
                      dataSize);
}

seos_err_t
OS_CryptoDigest_finalize(
    OS_CryptoDigestH hDigest,
    void*            digest,
    size_t*          digestSize)
{
    return PROXY_CALL(hDigest, Digest_finalize, PROXY_GET_OBJ(hDigest), digest,
                      digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
OS_CryptoSignature_init(
    OS_CryptoSignatureH*         hSig,
    const OS_CryptoH             self,
    const OS_CryptoKeyH          hPrvKey,
    const OS_CryptoKeyH          hPubKey,
    const OS_CryptoSignature_Alg sigAlgorithm,
    const OS_CryptoDigest_Alg    digAlgorithm)
{
    seos_err_t err;

    PROXY_INIT(*hSig, self);
    if ((err = PROXY_CALL(*hSig, Signature_init, PROXY_GET_SIG_PTR(*hSig),
                          sigAlgorithm, digAlgorithm,
                          PROXY_GET_OBJ(hPrvKey), PROXY_GET_OBJ(hPubKey))) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hSig);
    }

    return err;
}

seos_err_t
OS_CryptoSignature_free(
    OS_CryptoSignatureH hSig)
{
    seos_err_t err;

    err = PROXY_CALL(hSig, Signature_free, PROXY_GET_OBJ(hSig));
    PROXY_FREE(hSig);

    return err;
}

seos_err_t
OS_CryptoSignature_sign(
    OS_CryptoSignatureH hSig,
    const void*         hash,
    const size_t        hashSize,
    void*               signature,
    size_t*             signatureSize)
{
    return PROXY_CALL(hSig, Signature_sign, PROXY_GET_OBJ(hSig), hash, hashSize,
                      signature, signatureSize);
}

seos_err_t
OS_CryptoSignature_verify(
    OS_CryptoSignatureH hSig,
    const void*         hash,
    const size_t        hashSize,
    const void*         signature,
    const size_t        signatureSize)
{
    return PROXY_CALL(hSig, Signature_verify, PROXY_GET_OBJ(hSig), hash, hashSize,
                      signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
OS_CryptoAgreement_init(
    OS_CryptoAgreementH*         hAgree,
    const OS_CryptoH             self,
    const OS_CryptoKeyH          hPrvKey,
    const OS_CryptoAgreement_Alg algorithm)
{
    seos_err_t err;

    PROXY_INIT(*hAgree, self);
    if ((err = PROXY_CALL(*hAgree, Agreement_init, PROXY_GET_AGREE_PTR(*hAgree),
                          algorithm, PROXY_GET_OBJ(hPrvKey))) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hAgree);
    }

    return err;
}

seos_err_t
OS_CryptoAgreement_free(
    OS_CryptoAgreementH hAgree)
{
    seos_err_t err;

    err = PROXY_CALL(hAgree, Agreement_free, PROXY_GET_OBJ(hAgree));
    PROXY_FREE(hAgree);

    return err;
}

seos_err_t
OS_CryptoAgreement_agree(
    OS_CryptoAgreementH hAgree,
    const OS_CryptoKeyH hPubKey,
    void*               shared,
    size_t*             sharedSize)
{
    return PROXY_CALL(hAgree, Agreement_agree, PROXY_GET_OBJ(hAgree),
                      PROXY_GET_OBJ(hPubKey), shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
OS_CryptoKey_generate(
    OS_CryptoKeyH*           hKey,
    const OS_CryptoH         self,
    const OS_CryptoKey_Spec* spec)
{
    seos_err_t err;

    PROXY_INIT(*hKey, self);
    if ((err = PROXY_CALL(*hKey, Key_generate, PROXY_GET_KEY_PTR(*hKey),
                          spec)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hKey);
    }

    return err;
}

seos_err_t
OS_CryptoKey_import(
    OS_CryptoKeyH*           hKey,
    const OS_CryptoH         self,
    const OS_CryptoKey_Data* keyData)
{
    seos_err_t err;

    PROXY_INIT(*hKey, self);
    if ((err = PROXY_CALL(*hKey, Key_import, PROXY_GET_KEY_PTR(*hKey),
                          keyData)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hKey);
    }

    return err;
}

seos_err_t
OS_CryptoKey_makePublic(
    OS_CryptoKeyH*              hPubKey,
    const OS_CryptoH            self,
    const OS_CryptoKeyH         hPrvKey,
    const OS_CryptoKey_Attribs* attribs)
{
    seos_err_t err;

    PROXY_INIT(*hPubKey, self);
    if ((err = PROXY_CALL(*hPubKey, Key_makePublic, PROXY_GET_KEY_PTR(*hPubKey),
                          PROXY_GET_OBJ(hPrvKey), attribs)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hPubKey);
    }

    return err;
}

seos_err_t
OS_CryptoKey_free(
    OS_CryptoKeyH hKey)
{
    return PROXY_CALL(hKey, Key_free, PROXY_GET_OBJ(hKey));
}

seos_err_t
OS_CryptoKey_export(
    const OS_CryptoKeyH hKey,
    OS_CryptoKey_Data*  keyData)
{
    return PROXY_CALL(hKey, Key_export, PROXY_GET_OBJ(hKey), keyData);
}

seos_err_t
OS_CryptoKey_getParams(
    const OS_CryptoKeyH hKey,
    void*               keyParams,
    size_t*             paramSize)
{
    return PROXY_CALL(hKey, Key_getParams, PROXY_GET_OBJ(hKey), keyParams,
                      paramSize);
}

seos_err_t
OS_CryptoKey_getAttribs(
    const OS_CryptoKeyH   hKey,
    OS_CryptoKey_Attribs* attribs)
{
    return PROXY_CALL(hKey, Key_getAttribs, PROXY_GET_OBJ(hKey), attribs);
}

seos_err_t
OS_CryptoKey_loadParams(
    OS_CryptoH               self,
    const OS_CryptoKey_Param name,
    void*                    keyParams,
    size_t*                  paramSize)
{
    return CALL(self, Key_loadParams, name, keyParams, paramSize);
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
OS_CryptoCipher_init(
    OS_CryptoCipherH*         hCipher,
    const OS_CryptoH          self,
    const OS_CryptoKeyH       hKey,
    const OS_CryptoCipher_Alg algorithm,
    const void*               iv,
    const size_t              ivSize)
{
    seos_err_t err;

    PROXY_INIT(*hCipher, self);
    if ((err = PROXY_CALL(*hCipher, Cipher_init, PROXY_GET_CIPHER_PTR(*hCipher),
                          algorithm, PROXY_GET_OBJ(hKey), iv, ivSize)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hCipher);
    }

    return err;
}

seos_err_t
OS_CryptoCipher_free(
    OS_CryptoCipherH hCipher)
{
    seos_err_t err;

    err = PROXY_CALL(hCipher, Cipher_free, PROXY_GET_OBJ(hCipher));
    PROXY_FREE(hCipher);

    return err;
}

seos_err_t
OS_CryptoCipher_process(
    OS_CryptoCipherH hCipher,
    const void*      input,
    const size_t     inputSize,
    void*            output,
    size_t*          outputSize)
{
    return PROXY_CALL(hCipher, Cipher_process, PROXY_GET_OBJ(hCipher), input,
                      inputSize, output, outputSize);
}

seos_err_t
OS_CryptoCipher_start(
    OS_CryptoCipherH hCipher,
    const void*      ad,
    const size_t     adSize)
{
    return PROXY_CALL(hCipher, Cipher_start, PROXY_GET_OBJ(hCipher), ad, adSize);
}

seos_err_t
OS_CryptoCipher_finalize(
    OS_CryptoCipherH hCipher,
    void*            output,
    size_t*          outputSize)
{
    return PROXY_CALL(hCipher, Cipher_finalize, PROXY_GET_OBJ(hCipher), output,
                      outputSize);
}