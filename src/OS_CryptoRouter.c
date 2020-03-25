/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)

#include "OS_CryptoRouter.h"
#include "OS_CryptoRpcClient.h"
#include "OS_CryptoLib.h"

#include <string.h>

// -------------------------- defines/types/variables --------------------------

/*
 * The router as a local instance of the LIB and a remote instance connected
 * via RPC client. Whenever a new Key is created (Key_generate, Key_import, etc.)
 * the "exportable" attribute of this key is check. Exportable keys are sent to
 * the LIB and created there. Non-exportable keys are sent to the RPC Client (and
 * from there to the server).
 *
 * The locality of Agreement, Signature and Cipher objects then follows from the
 * locality of the associated keys. That means those objects will be created by
 * the LIB or RPC server according to where the associated key resides.
 *
 * Digest and Mac (and Rng) operations are always done via the LIB and thus local,
 * because they do not need any keys.
 */

// Call a function from the a given vtable, check if pointers are non-NULL,
// including the function pointer
#define CALL(c, v, f, ...)                                          \
    (NULL == c) ? SEOS_ERROR_INVALID_PARAMETER :                    \
        (NULL == ((OS_CryptoRouter *)c)->v.vtable->f) ?             \
            SEOS_ERROR_NOT_SUPPORTED :                              \
            ((OS_CryptoRouter *)c)->v.vtable->f(                    \
                ((OS_CryptoRouter *)c)->v.context, ## __VA_ARGS__   \
            )
#define CALL_LIB(c, f, ...) \
    CALL(c, lib, f, ## __VA_ARGS__)
#define CALL_CLI(c, f, ...) \
    CALL(c, client, f, ## __VA_ARGS__)

// Route call to LIB/CLIENT based on location of object
#define ROUTE_CALL(e, c, f, o, ...)             \
    (CALL_LIB(c, e, o) == SEOS_SUCCESS) ?       \
        CALL_LIB(c, f, o, ## __VA_ARGS__) :     \
        CALL_CLI(c, f, o, ## __VA_ARGS__)
#define ROUTE_KEY_CALL(c, f, o, ...) \
    ROUTE_CALL(Key_exists, c, f, o, ## ## __VA_ARGS__)
#define ROUTE_CIPHER_CALL(c, f, o, ...) \
    ROUTE_CALL(Cipher_exists, c, f, o, ## ## __VA_ARGS__)
#define ROUTE_SIG_CALL(c, f, o, ...) \
    ROUTE_CALL(Signature_exists, c, f, o, ## ## __VA_ARGS__)
#define ROUTE_AGR_CALL(c, f, o, ...) \
    ROUTE_CALL(Agreement_exists, c, f, o, ## ## __VA_ARGS__)

struct OS_CryptoRouter
{
    OS_CryptoImpl lib;
    OS_CryptoImpl client;
    OS_Crypto_Memory memIf;
};

// -------------------------------- RNG API ------------------------------------

static seos_err_t
Rng_getBytes(
    void*                   ctx,
    const OS_CryptoRng_Flag flags,
    void*                   buf,
    const size_t            bufSize)
{
    return CALL_LIB(ctx, Rng_getBytes, flags, buf, bufSize);
}

static seos_err_t
Rng_reseed(
    void*        ctx,
    const void*  seed,
    const size_t seedSize)
{
    return CALL_LIB(ctx, Rng_reseed, seed, seedSize);
}

// ------------------------------- MAC API -------------------------------------

static seos_err_t
Mac_init(
    void*                  ctx,
    OS_CryptoLibMac**      pMacObj,
    const OS_CryptoMac_Alg algorithm)
{
    return CALL_LIB(ctx, Mac_init, pMacObj, algorithm);
}

static seos_err_t
Mac_exists(
    void*                  ctx,
    const OS_CryptoLibMac* macObj)
{
    return CALL_LIB(ctx, Mac_exists, macObj);
}

static seos_err_t
Mac_free(
    void*            ctx,
    OS_CryptoLibMac* macObj)
{
    return CALL_LIB(ctx, Mac_free, macObj);
}

static seos_err_t
Mac_start(
    void*            ctx,
    OS_CryptoLibMac* macObj,
    const void*      secret,
    const size_t     secretSize)
{
    return CALL_LIB(ctx, Mac_start, macObj, secret, secretSize);
}

static seos_err_t
Mac_process(
    void*            ctx,
    OS_CryptoLibMac* macObj,
    const void*      data,
    const size_t     dataSize)
{
    return CALL_LIB(ctx, Mac_process, macObj, data, dataSize);
}

static seos_err_t
Mac_finalize(
    void*            ctx,
    OS_CryptoLibMac* macObj,
    void*            mac,
    size_t*          macSize)
{
    return CALL_LIB(ctx, Mac_finalize, macObj, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

static seos_err_t
Digest_init(
    void*                     ctx,
    OS_CryptoLibDigest**      pDigestObj,
    const OS_CryptoDigest_Alg algorithm)
{
    return CALL_LIB(ctx, Digest_init, pDigestObj, algorithm);
}

static seos_err_t
Digest_exists(
    void*                     ctx,
    const OS_CryptoLibDigest* digestObj)
{
    return CALL_LIB(ctx, Digest_exists, digestObj);
}

static seos_err_t
Digest_free(
    void*               ctx,
    OS_CryptoLibDigest* digestObj)
{
    return CALL_LIB(ctx, Digest_free, digestObj);
}

static seos_err_t
Digest_clone(
    void*                     ctx,
    OS_CryptoLibDigest*       dstDigObj,
    const OS_CryptoLibDigest* srcDigObj)
{
    return CALL_LIB(ctx, Digest_clone, dstDigObj, srcDigObj);
}

static seos_err_t
Digest_process(
    void*               ctx,
    OS_CryptoLibDigest* digestObj,
    const void*         data,
    const size_t        dataSize)
{
    return CALL_LIB(ctx, Digest_process, digestObj, data, dataSize);
}

static seos_err_t
Digest_finalize(
    void*               ctx,
    OS_CryptoLibDigest* digestObj,
    void*               digest,
    size_t*             digestSize)
{
    return CALL_LIB(ctx, Digest_finalize, digestObj, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

static seos_err_t
Signature_init(
    void*                        ctx,
    OS_CryptoLibSignature**      pSigObj,
    const OS_CryptoSignature_Alg algorithm,
    const OS_CryptoDigest_Alg    digest,
    const OS_CryptoLibKey*       prvKey,
    const OS_CryptoLibKey*       pubKey)
{
    seos_err_t err;

    if (NULL != prvKey)
    {
        err = CALL_LIB(ctx, Key_exists, prvKey) == SEOS_SUCCESS ?
              CALL_LIB(ctx, Signature_init, pSigObj, algorithm, digest, prvKey, pubKey) :
              CALL_CLI(ctx, Signature_init, pSigObj, algorithm, digest, prvKey, pubKey);
    }
    else if (NULL != pubKey)
    {
        err = CALL_LIB(ctx, Key_exists, pubKey) == SEOS_SUCCESS ?
              CALL_LIB(ctx, Signature_init, pSigObj, algorithm, digest, prvKey, pubKey) :
              CALL_CLI(ctx, Signature_init, pSigObj, algorithm, digest, prvKey, pubKey);
    }
    else
    {
        err = SEOS_ERROR_INVALID_PARAMETER;
    }

    return err;
}

static seos_err_t
Signature_exists(
    void*                        ctx,
    const OS_CryptoLibSignature* sigObj)
{
    return CALL_LIB(ctx, Signature_exists, sigObj) == SEOS_SUCCESS ?
           SEOS_SUCCESS :
           CALL_CLI(ctx, Signature_exists, sigObj);
}

static seos_err_t
Signature_free(
    void*                  ctx,
    OS_CryptoLibSignature* sigObj)
{
    return ROUTE_SIG_CALL(ctx, Signature_free, sigObj);
}

static seos_err_t
Signature_sign(
    void*                  ctx,
    OS_CryptoLibSignature* sigObj,
    const void*            hash,
    const size_t           hashSize,
    void*                  signature,
    size_t*                signatureSize)
{
    return ROUTE_SIG_CALL(ctx, Signature_sign, sigObj, hash, hashSize, signature,
                          signatureSize);
}

static seos_err_t
Signature_verify(
    void*                  ctx,
    OS_CryptoLibSignature* sigObj,
    const void*            hash,
    const size_t           hashSize,
    const void*            signature,
    const size_t           signatureSize)
{
    return ROUTE_SIG_CALL(ctx, Signature_verify, sigObj, hash, hashSize, signature,
                          signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    void*                        ctx,
    OS_CryptoLibAgreement**      pAgrObj,
    const OS_CryptoAgreement_Alg algorithm,
    const OS_CryptoLibKey*       prvKey)
{
    return CALL_LIB(ctx, Key_exists, prvKey) == SEOS_SUCCESS ?
           CALL_LIB(ctx, Agreement_init, pAgrObj, algorithm, prvKey) :
           CALL_CLI(ctx, Agreement_init, pAgrObj, algorithm, prvKey);
}

static seos_err_t
Agreement_exists(
    void*                        ctx,
    const OS_CryptoLibAgreement* agrObj)
{
    return CALL_LIB(ctx, Agreement_exists, agrObj) == SEOS_SUCCESS ?
           SEOS_SUCCESS :
           CALL_CLI(ctx, Agreement_exists, agrObj);
}

static seos_err_t
Agreement_free(
    void*                  ctx,
    OS_CryptoLibAgreement* agrObj)
{
    return ROUTE_AGR_CALL(ctx, Agreement_free, agrObj);
}

static seos_err_t
Agreement_agree(
    void*                  ctx,
    OS_CryptoLibAgreement* agrObj,
    const OS_CryptoLibKey* pubKey,
    void*                  shared,
    size_t*                sharedSize)
{
    return ROUTE_AGR_CALL(ctx, Agreement_agree, agrObj, pubKey, shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

static seos_err_t
Key_generate(
    void*                    ctx,
    OS_CryptoLibKey**        pKeyObj,
    const OS_CryptoKey_Spec* spec)
{
    if (NULL == spec)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return spec->key.attribs.exportable ?
           CALL_LIB(ctx, Key_generate, pKeyObj, spec) :
           CALL_CLI(ctx, Key_generate, pKeyObj, spec);
}

static seos_err_t
Key_makePublic(
    void*                       ctx,
    OS_CryptoLibKey**           pPubKeyObj,
    const OS_CryptoLibKey*      prvKeyObj,
    const OS_CryptoKey_Attribs* attribs)
{
    if (NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return attribs->exportable ?
           CALL_LIB(ctx, Key_makePublic, pPubKeyObj, prvKeyObj, attribs) :
           CALL_CLI(ctx, Key_makePublic, pPubKeyObj, prvKeyObj, attribs);
}

static seos_err_t
Key_import(
    void*                    ctx,
    OS_CryptoLibKey**        pKeyObj,
    const OS_CryptoKey_Data* keyData)
{
    if (NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return keyData->attribs.exportable ?
           CALL_LIB(ctx, Key_import, pKeyObj, keyData) :
           CALL_CLI(ctx, Key_import, pKeyObj, keyData);
}

static seos_err_t
Key_export(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj,
    OS_CryptoKey_Data*     keyData)
{
    return ROUTE_KEY_CALL(ctx, Key_export, keyObj, keyData);
}

static seos_err_t
Key_getParams(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj,
    void*                  keyParams,
    size_t*                paramSize)
{
    return ROUTE_KEY_CALL(ctx, Key_getParams, keyObj, keyParams, paramSize);
}

static seos_err_t
Key_getAttribs(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj,
    OS_CryptoKey_Attribs*  attribs)
{
    return ROUTE_KEY_CALL(ctx, Key_getAttribs, keyObj, attribs);
}

static seos_err_t
Key_loadParams(
    void*                    ctx,
    const OS_CryptoKey_Param name,
    void*                    keyParams,
    size_t*                  paramSize)
{
    return CALL_LIB(ctx, Key_loadParams, name, keyParams, paramSize);
}

static seos_err_t
Key_exists(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj)
{
    return CALL_LIB(ctx, Key_exists, keyObj) == SEOS_SUCCESS ?
           SEOS_SUCCESS :
           CALL_CLI(ctx, Key_exists, keyObj);
}

static seos_err_t
Key_free(
    void*            ctx,
    OS_CryptoLibKey* keyObj)
{
    return ROUTE_KEY_CALL(ctx, Key_free, keyObj);
}

// ------------------------------ Cipher API -----------------------------------

static seos_err_t
Cipher_init(
    void*                     ctx,
    OS_CryptoLibCipher**      pCipherObj,
    const OS_CryptoCipher_Alg algorithm,
    const OS_CryptoLibKey*    key,
    const void*               iv,
    const size_t              ivSize)
{
    return CALL_LIB(ctx, Key_exists, key) == SEOS_SUCCESS ?
           CALL_LIB(ctx, Cipher_init, pCipherObj, algorithm, key, iv, ivSize) :
           CALL_CLI(ctx, Cipher_init, pCipherObj, algorithm, key, iv, ivSize);
}

static seos_err_t
Cipher_exists(
    void*                     ctx,
    const OS_CryptoLibCipher* cipherObj)
{
    return CALL_LIB(ctx, Cipher_exists, cipherObj) == SEOS_SUCCESS ?
           SEOS_SUCCESS :
           CALL_CLI(ctx, Cipher_exists, cipherObj);
}

static seos_err_t
Cipher_free(
    void*               ctx,
    OS_CryptoLibCipher* cipherObj)

{
    return ROUTE_CIPHER_CALL(ctx, Cipher_free, cipherObj);
}

static seos_err_t
Cipher_process(
    void*               ctx,
    OS_CryptoLibCipher* cipherObj,
    const void*         input,
    const size_t        inputSize,
    void*               output,
    size_t*             outputSize)
{
    return ROUTE_CIPHER_CALL(ctx, Cipher_process, cipherObj, input, inputSize,
                             output, outputSize);
}

static seos_err_t
Cipher_start(
    void*               ctx,
    OS_CryptoLibCipher* cipherObj,
    const void*         data,
    const size_t        dataSize)
{
    return ROUTE_CIPHER_CALL(ctx, Cipher_start, cipherObj, data, dataSize);
}

static seos_err_t
Cipher_finalize(
    void*               ctx,
    OS_CryptoLibCipher* cipherObj,
    void*               tag,
    size_t*             tagSize)
{
    return ROUTE_CIPHER_CALL(ctx, Cipher_finalize, cipherObj, tag, tagSize);
}

// ------------------------------- init/free -----------------------------------

static const OS_CryptoImpl_Vtable OS_CryptoRouter_vtable =
{
    .Rng_getBytes        = Rng_getBytes,
    .Rng_reseed          = Rng_reseed,
    .Mac_init            = Mac_init,
    .Mac_exists          = Mac_exists,
    .Mac_free            = Mac_free,
    .Mac_start           = Mac_start,
    .Mac_process         = Mac_process,
    .Mac_finalize        = Mac_finalize,
    .Digest_init         = Digest_init,
    .Digest_exists       = Digest_exists,
    .Digest_free         = Digest_free,
    .Digest_clone        = Digest_clone,
    .Digest_process      = Digest_process,
    .Digest_finalize     = Digest_finalize,
    .Key_generate        = Key_generate,
    .Key_makePublic      = Key_makePublic,
    .Key_import          = Key_import,
    .Key_export          = Key_export,
    .Key_getParams       = Key_getParams,
    .Key_getAttribs      = Key_getAttribs,
    .Key_loadParams      = Key_loadParams,
    .Key_exists          = Key_exists,
    .Key_free            = Key_free,
    .Signature_init      = Signature_init,
    .Signature_exists    = Signature_exists,
    .Signature_free      = Signature_free,
    .Signature_sign      = Signature_sign,
    .Signature_verify    = Signature_verify,
    .Agreement_init      = Agreement_init,
    .Agreement_exists    = Agreement_exists,
    .Agreement_free      = Agreement_free,
    .Agreement_agree     = Agreement_agree,
    .Cipher_init         = Cipher_init,
    .Cipher_exists       = Cipher_exists,
    .Cipher_free         = Cipher_free,
    .Cipher_process      = Cipher_process,
    .Cipher_start        = Cipher_start,
    .Cipher_finalize     = Cipher_finalize,
};

seos_err_t
OS_CryptoRouter_init(
    OS_CryptoImpl*                impl,
    const OS_Crypto_Memory*       memIf,
    const OS_CryptoRouter_Config* cfg)
{
    seos_err_t err;
    OS_CryptoRouter* self;

    if (NULL == impl || NULL == memIf || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((self = memIf->malloc(sizeof(OS_CryptoRouter))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    impl->context = self;
    impl->vtable  = &OS_CryptoRouter_vtable;;
    self->memIf   = *memIf;

    if ((err = OS_CryptoLib_init(&self->lib, memIf, &cfg->lib)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    if ((err = OS_CryptoRpcClient_init(&self->client, memIf,
                                       &cfg->client)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    OS_CryptoLib_free(self->lib.context);
err0:
    self->memIf.free(self);

    return err;
}

seos_err_t
OS_CryptoRouter_free(
    OS_CryptoRouter* self)
{
    seos_err_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = OS_CryptoRpcClient_free(self->client.context)) != SEOS_SUCCESS)
    {
        return err;
    }
    err = OS_CryptoLib_free(self->lib.context);

    self->memIf.free(self);

    return err;
}

#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */