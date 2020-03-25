/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)

#include "OS_CryptoRpcClient.h"
#include "OS_CryptoRpcServer.h"

#include "compiler.h"

#include <string.h>
#include <sys/user.h>

// -------------------------- defines/types/variables --------------------------

struct OS_CryptoRpcClient
{
    OS_Crypto_Memory memIf;
    /**
     * The client's address of the dataport shared with the server
     */
    void* dataPort;
};

// -------------------------------- RNG API ------------------------------------

static seos_err_t
Rng_getBytes(
    void*                   ctx,
    const OS_CryptoRng_Flag flags,
    void*                   buf,
    const size_t            bufSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == buf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (bufSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = OS_CryptoRpcServer_Rng_getBytes(flags, bufSize)) == SEOS_SUCCESS)
    {
        memcpy(buf, self->dataPort, bufSize);
    }

    return err;
}

static seos_err_t
Rng_reseed(
    void*        ctx,
    const void*  seed,
    const size_t seedSize)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == seed)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (seedSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, seed, seedSize);
    return OS_CryptoRpcServer_Rng_reseed(seedSize);
}

// ------------------------------- MAC API -------------------------------------

static seos_err_t
Mac_init(
    void*                  ctx,
    OS_CryptoLibMac**      pMacObj,
    const OS_CryptoMac_Alg algorithm)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Mac_init(pMacObj, algorithm);
}

static seos_err_t
Mac_exists(
    void*                  ctx,
    const OS_CryptoLibMac* macObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Mac_exists(macObj);
}

static seos_err_t
Mac_free(
    void*            ctx,
    OS_CryptoLibMac* macObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Mac_free(macObj);
}

static seos_err_t
Mac_start(
    void*            ctx,
    OS_CryptoLibMac* macObj,
    const void*      secret,
    const size_t     secretSize)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == secret)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (secretSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, secret, secretSize);
    return OS_CryptoRpcServer_Mac_start(macObj, secretSize);
}

static seos_err_t
Mac_process(
    void*            ctx,
    OS_CryptoLibMac* macObj,
    const void*      data,
    const size_t     dataSize)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, data, dataSize);
    return OS_CryptoRpcServer_Mac_process(macObj, dataSize);
}

static seos_err_t
Mac_finalize(
    void*            ctx,
    OS_CryptoLibMac* macObj,
    void*            mac,
    size_t*          macSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == mac || NULL == macSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*macSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = OS_CryptoRpcServer_Mac_finalize(macObj, macSize)) == SEOS_SUCCESS)
    {
        memcpy(mac, self->dataPort, *macSize);
    }

    return err;
}

// ------------------------------ Digest API -----------------------------------

static seos_err_t
Digest_init(
    void*                     ctx,
    OS_CryptoLibDigest**      pDigestObj,
    const OS_CryptoDigest_Alg algorithm)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Digest_init(pDigestObj, algorithm);
}

static seos_err_t
Digest_exists(
    void*                     ctx,
    const OS_CryptoLibDigest* digestObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Digest_exists(digestObj);
}

static seos_err_t
Digest_free(
    void*               ctx,
    OS_CryptoLibDigest* digestObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Digest_free(digestObj);
}

static seos_err_t
Digest_clone(
    void*                     ctx,
    OS_CryptoLibDigest*       dstDigObj,
    const OS_CryptoLibDigest* srcDigObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Digest_clone(dstDigObj, srcDigObj);
}

static seos_err_t
Digest_process(
    void*               ctx,
    OS_CryptoLibDigest* digestObj,
    const void*         data,
    const size_t        dataSize)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, data, dataSize);
    return OS_CryptoRpcServer_Digest_process(digestObj, dataSize);
}

static seos_err_t
Digest_finalize(
    void*               ctx,
    OS_CryptoLibDigest* digestObj,
    void*               digest,
    size_t*             digestSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == digest || NULL == digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*digestSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = OS_CryptoRpcServer_Digest_finalize(digestObj,
                                                  digestSize)) == SEOS_SUCCESS)
    {
        memcpy(digest, self->dataPort, *digestSize);
    }

    return err;
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
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Signature_init(pSigObj, algorithm, digest, prvKey,
                                             pubKey);
}

static seos_err_t
Signature_exists(
    void*                        ctx,
    const OS_CryptoLibSignature* signatureObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Signature_exists(signatureObj);
}

static seos_err_t
Signature_free(
    void*                  ctx,
    OS_CryptoLibSignature* sigObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Signature_free(sigObj);
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
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    else if (*signatureSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, hash, hashSize);
    if ((err = OS_CryptoRpcServer_Signature_sign(sigObj, hashSize,
                                                 signatureSize)) == SEOS_SUCCESS)
    {
        memcpy(signature, self->dataPort, *signatureSize);
    }

    return err;
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
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == ctx || NULL == hash || NULL == signature)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, hash, hashSize);
    memcpy(self->dataPort + hashSize, signature, signatureSize);
    return OS_CryptoRpcServer_Signature_verify(sigObj, hashSize, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    void*                        ctx,
    OS_CryptoLibAgreement**      pAgrObj,
    const OS_CryptoAgreement_Alg algorithm,
    const OS_CryptoLibKey*       prvKey)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Agreement_init(pAgrObj, algorithm, prvKey);
}

static seos_err_t
Agreement_exists(
    void*                        ctx,
    const OS_CryptoLibAgreement* agrObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Agreement_exists(agrObj);
}

static seos_err_t
Agreement_free(
    void*                  ctx,
    OS_CryptoLibAgreement* agrObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Agreement_free(agrObj);
}

static seos_err_t
Agreement_agree(
    void*                  ctx,
    OS_CryptoLibAgreement* agrObj,
    const OS_CryptoLibKey* pubKey,
    void*                  shared,
    size_t*                sharedSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*sharedSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = OS_CryptoRpcServer_Agreement_agree(agrObj, pubKey,
                                                  sharedSize)) == SEOS_SUCCESS)
    {
        memcpy(shared, self->dataPort, *sharedSize);
    }

    return err;
}

// -------------------------------- Key API ------------------------------------

static seos_err_t
Key_generate(
    void*                    ctx,
    OS_CryptoLibKey**        pKeyObj,
    const OS_CryptoKey_Spec* spec)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == pKeyObj || NULL == spec)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->dataPort, spec, sizeof(OS_CryptoKey_Spec));
    return OS_CryptoRpcServer_Key_generate(pKeyObj);
}

static seos_err_t
Key_makePublic(
    void*                       ctx,
    OS_CryptoLibKey**           pPubKeyObj,
    const OS_CryptoLibKey*      prvKeyObj,
    const OS_CryptoKey_Attribs* attribs)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == pPubKeyObj || NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->dataPort, attribs, sizeof(OS_CryptoKey_Attribs));
    return OS_CryptoRpcServer_Key_makePublic(pPubKeyObj, prvKeyObj);
}

static seos_err_t
Key_import(
    void*                    ctx,
    OS_CryptoLibKey**        pKeyObj,
    const OS_CryptoKey_Data* keyData)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == pKeyObj || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->dataPort, keyData, sizeof(OS_CryptoKey_Data));
    return OS_CryptoRpcServer_Key_import(pKeyObj);
}

static seos_err_t
Key_export(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj,
    OS_CryptoKey_Data*     keyData)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = OS_CryptoRpcServer_Key_export(keyObj)) == SEOS_SUCCESS)
    {
        memcpy(keyData, self->dataPort, sizeof(OS_CryptoKey_Data));
    }

    return err;
}

static seos_err_t
Key_getParams(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj,
    void*                  keyParams,
    size_t*                paramSize)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = OS_CryptoRpcServer_Key_getParams(keyObj,
                                                paramSize)) == SEOS_SUCCESS)
    {
        memcpy(keyParams, self->dataPort, *paramSize);
    }

    return err;
}

static seos_err_t
Key_getAttribs(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj,
    OS_CryptoKey_Attribs*  attribs)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = OS_CryptoRpcServer_Key_getAttribs(keyObj)) == SEOS_SUCCESS)
    {
        memcpy(attribs, self->dataPort, sizeof(OS_CryptoKey_Attribs));
    }

    return err;
}

static seos_err_t
Key_loadParams(
    void*                    ctx,
    const OS_CryptoKey_Param name,
    void*                    keyParams,
    size_t*                  paramSize)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = OS_CryptoRpcServer_Key_loadParams(name,
                                                 paramSize)) == SEOS_SUCCESS)
    {
        memcpy(keyParams, self->dataPort, *paramSize);
    }

    return err;
}

static seos_err_t
Key_exists(
    void*                  ctx,
    const OS_CryptoLibKey* keyObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Key_exists(keyObj);
}

static seos_err_t
Key_free(
    void*            ctx,
    OS_CryptoLibKey* keyObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Key_free(keyObj);
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
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == pCipherObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (iv != NULL)
    {
        if (ivSize > OS_Crypto_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->dataPort, iv, ivSize);
    }

    return OS_CryptoRpcServer_Cipher_init(pCipherObj, algorithm, key, ivSize);
}

static seos_err_t
Cipher_exists(
    void*                     ctx,
    const OS_CryptoLibCipher* cipherObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Cipher_exists(cipherObj);
}

static seos_err_t
Cipher_free(
    void*               ctx,
    OS_CryptoLibCipher* cipherObj)
{
    UNUSED_VAR(ctx);
    return OS_CryptoRpcServer_Cipher_free(cipherObj);
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
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == input || NULL == output || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    else if (*outputSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, input, inputSize);
    if ((err = OS_CryptoRpcServer_Cipher_process(cipherObj, inputSize,
                                                 outputSize)) == SEOS_SUCCESS)
    {
        memcpy(output, self->dataPort, *outputSize);
    }

    return err;
}

static seos_err_t
Cipher_start(
    void*               ctx,
    OS_CryptoLibCipher* cipherObj,
    const void*         data,
    const size_t        dataSize)
{
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL != data)
    {
        if (dataSize > OS_Crypto_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->dataPort, data, dataSize);
    }

    return OS_CryptoRpcServer_Cipher_start(cipherObj, dataSize);
}

static seos_err_t
Cipher_finalize(
    void*               ctx,
    OS_CryptoLibCipher* cipherObj,
    void*               tag,
    size_t*             tagSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoRpcClient* self = (OS_CryptoRpcClient*) ctx;

    if (NULL == self || NULL == tag || NULL == tagSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*tagSize > OS_Crypto_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, tag, *tagSize);
    if ((err = OS_CryptoRpcServer_Cipher_finalize(cipherObj,
                                                  tagSize)) == SEOS_SUCCESS)
    {
        memcpy(tag, self->dataPort, *tagSize);
    }

    return err;
}

// ------------------------------- init/free -----------------------------------

static const OS_CryptoImpl_Vtable OS_CryptoRpcClient_vtable =
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
OS_CryptoRpcClient_init(
    OS_CryptoImpl*                   impl,
    const OS_Crypto_Memory*          memIf,
    const OS_CryptoRpcClient_Config* cfg)
{
    OS_CryptoRpcClient* self;

    if (NULL == impl || NULL == memIf || NULL == cfg || NULL == cfg->dataPort)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((self = memIf->malloc(sizeof(OS_CryptoRpcClient))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    impl->context  = self;
    impl->vtable   = &OS_CryptoRpcClient_vtable;
    self->dataPort = cfg->dataPort;
    self->memIf    = *memIf;

    return SEOS_SUCCESS;
}

seos_err_t
OS_CryptoRpcClient_free(
    OS_CryptoRpcClient* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    self->memIf.free(self);

    return SEOS_SUCCESS;
}

#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */