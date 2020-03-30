/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_CryptoLib.h"

#include "util/PtrVector.h"

#include <string.h>

// -------------------------- defines/types/variables --------------------------

#define OS_CryptoLib_SIZE_BUFFER OS_Crypto_SIZE_DATAPORT

struct OS_CryptoLib
{
    OS_Crypto_Memory_t memIf;
    OS_CryptoLibRng_t* rng;
    PtrVector keyObjects;
    PtrVector macObjects;
    PtrVector digestObjects;
    PtrVector cipherObjects;
    PtrVector signatureObjects;
    PtrVector agreementObjects;
    /**
     * When we have a function that takes an input buffer and produces an output
     * buffer, we copy the inputs to this buffer internally, so the caller can
     * use the identical buffer as input/output.
     */
    uint8_t buffer[OS_CryptoLib_SIZE_BUFFER];
};

// -------------------------------- RNG API ------------------------------------

static seos_err_t
Rng_getBytes(
    void*                     ctx,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (bufSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return OS_CryptoLibRng_getBytes(self->rng, flags, buf, bufSize);
}

static seos_err_t
Rng_reseed(
    void*        ctx,
    const void*  seed,
    const size_t seedSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (seedSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return OS_CryptoLibRng_reSeed(self->rng, seed, seedSize);
}

// -------------------------------- MAC API ------------------------------------

static seos_err_t
Mac_init(
    void*                    ctx,
    OS_CryptoLibMac_t**      pMacObj,
    const OS_CryptoMac_Alg_t algorithm)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pMacObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = OS_CryptoLibMac_init(pMacObj, &self->memIf,
                                    algorithm)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->macObjects, *pMacObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    OS_CryptoLibMac_free(*pMacObj, &self->memIf);

    return err;
}

static seos_err_t
Mac_free(
    void*              ctx,
    OS_CryptoLibMac_t* macObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->macObjects, macObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PtrVector_remove(&self->macObjects, macObj);

    return OS_CryptoLibMac_free(macObj, &self->memIf);
}

static seos_err_t
Mac_exists(
    void*                    ctx,
    const OS_CryptoLibMac_t* macObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->macObjects, macObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SEOS_SUCCESS;
}

static seos_err_t
Mac_start(
    void*              ctx,
    OS_CryptoLibMac_t* macObj,
    const void*        secret,
    const size_t       secretSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (secretSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->macObjects, macObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibMac_start(macObj, secret, secretSize);
}

static seos_err_t
Mac_process(
    void*              ctx,
    OS_CryptoLibMac_t* macObj,
    const void*        data,
    const size_t       dataSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->macObjects, macObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibMac_process(macObj, data, dataSize);
}

static seos_err_t
Mac_finalize(
    void*              ctx,
    OS_CryptoLibMac_t* macObj,
    void*              mac,
    size_t*            macSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == macSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*macSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->macObjects, macObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibMac_finalize(macObj, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

static seos_err_t
Digest_init(
    void*                       ctx,
    OS_CryptoLibDigest_t**      pDigObj,
    const OS_CryptoDigest_Alg_t algorithm)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pDigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = OS_CryptoLibDigest_init(pDigObj, &self->memIf,
                                       algorithm)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->digestObjects, *pDigObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    OS_CryptoLibDigest_free(*pDigObj, &self->memIf);

    return err;
}

static seos_err_t
Digest_free(
    void*                 ctx,
    OS_CryptoLibDigest_t* digObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->digestObjects, digObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PtrVector_remove(&self->digestObjects, digObj);

    return OS_CryptoLibDigest_free(digObj, &self->memIf);
}

static seos_err_t
Digest_exists(
    void*                       ctx,
    const OS_CryptoLibDigest_t* digestObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->digestObjects, digestObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SEOS_SUCCESS;
}

static seos_err_t
Digest_clone(
    void*                       ctx,
    OS_CryptoLibDigest_t*       dstDigObj,
    const OS_CryptoLibDigest_t* srcDigObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->digestObjects, dstDigObj) ||
           !PtrVector_hasPtr(&self->digestObjects, srcDigObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibDigest_clone(dstDigObj, srcDigObj);
}

static seos_err_t
Digest_process(
    void*                 ctx,
    OS_CryptoLibDigest_t* digObj,
    const void*           data,
    const size_t          dataSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->digestObjects, digObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibDigest_process(digObj, data, dataSize);
}

static seos_err_t
Digest_finalize(
    void*                 ctx,
    OS_CryptoLibDigest_t* digObj,
    void*                 digest,
    size_t*               digestSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*digestSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->digestObjects, digObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibDigest_finalize(digObj, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

static seos_err_t
Signature_init(
    void*                          ctx,
    OS_CryptoLibSignature_t**      pSigObj,
    const OS_CryptoSignature_Alg_t algorithm,
    const OS_CryptoDigest_Alg_t    digest,
    const OS_CryptoLibKey_t*       prvKey,
    const OS_CryptoLibKey_t*       pubKey)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pSigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (prvKey != NULL && !PtrVector_hasPtr(&self->keyObjects, prvKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (pubKey != NULL && !PtrVector_hasPtr(&self->keyObjects, pubKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = OS_CryptoLibSignature_init(pSigObj, &self->memIf, algorithm,
                                          digest, prvKey, pubKey)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->signatureObjects, *pSigObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return err;

err0:
    OS_CryptoLibSignature_free(*pSigObj, &self->memIf);

    return err;
}

static seos_err_t
Signature_free(
    void*                    ctx,
    OS_CryptoLibSignature_t* sigObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->signatureObjects, sigObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PtrVector_remove(&self->signatureObjects, sigObj);

    return OS_CryptoLibSignature_free(sigObj, &self->memIf);
}

static seos_err_t
Signature_exists(
    void*                          ctx,
    const OS_CryptoLibSignature_t* signatureObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->signatureObjects, signatureObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SEOS_SUCCESS;
}

static seos_err_t
Signature_sign(
    void*                    ctx,
    OS_CryptoLibSignature_t* sigObj,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == hash || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > OS_CryptoLib_SIZE_BUFFER ||
             *signatureSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping hash/signature buffers
    memcpy(self->buffer, hash, hashSize);
    return !PtrVector_hasPtr(&self->signatureObjects, sigObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibSignature_sign(sigObj, self->rng, self->buffer,
                                      hashSize, signature, signatureSize);
}

static seos_err_t
Signature_verify(
    void*                    ctx,
    OS_CryptoLibSignature_t* sigObj,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->signatureObjects, sigObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibSignature_verify(sigObj, self->rng, hash, hashSize,
                                        signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    void*                          ctx,
    OS_CryptoLibAgreement_t**      pAgrObj,
    const OS_CryptoAgreement_Alg_t algorithm,
    const OS_CryptoLibKey_t*       prvKey)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pAgrObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, prvKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = OS_CryptoLibAgreement_init(pAgrObj, &self->memIf, algorithm,
                                          prvKey)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->agreementObjects, *pAgrObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    OS_CryptoLibAgreement_free(*pAgrObj, &self->memIf);

    return err;
}

static seos_err_t
Agreement_free(
    void*                    ctx,
    OS_CryptoLibAgreement_t* agrObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->agreementObjects, agrObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PtrVector_remove(&self->agreementObjects, agrObj);

    return OS_CryptoLibAgreement_free(agrObj, &self->memIf);
}

static seos_err_t
Agreement_exists(
    void*                          ctx,
    const OS_CryptoLibAgreement_t* agrObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->agreementObjects, agrObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SEOS_SUCCESS;
}

static seos_err_t
Agreement_agree(
    void*                    ctx,
    OS_CryptoLibAgreement_t* agrObj,
    const OS_CryptoLibKey_t* pubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*sharedSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, pubKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    return !PtrVector_hasPtr(&self->agreementObjects, agrObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibAgreement_agree(agrObj, self->rng, pubKey, shared,
                                       sharedSize);
}

// -------------------------------- Key API ------------------------------------

static seos_err_t
Key_generate(
    void*                      ctx,
    OS_CryptoLibKey_t**        pKeyObj,
    const OS_CryptoKey_Spec_t* spec)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = OS_CryptoLibKey_generate(pKeyObj, &self->memIf, self->rng,
                                        spec)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->keyObjects, *pKeyObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    OS_CryptoLibKey_free(*pKeyObj, &self->memIf);

    return err;
}

static seos_err_t
Key_import(
    void*                      ctx,
    OS_CryptoLibKey_t**        pKeyObj,
    const OS_CryptoKey_Data_t* keyData)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = OS_CryptoLibKey_import(pKeyObj, &self->memIf,
                                      keyData)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->keyObjects, *pKeyObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    OS_CryptoLibKey_free(*pKeyObj, &self->memIf);

    return err;
}

static seos_err_t
Key_makePublic(
    void*                        ctx,
    OS_CryptoLibKey_t**          pPubKeyObj,
    const OS_CryptoLibKey_t*     prvKeyObj,
    const OS_CryptoKey_Attrib_t* attribs)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pPubKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, prvKeyObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = OS_CryptoLibKey_makePublic(pPubKeyObj, &self->memIf, prvKeyObj,
                                          attribs)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->keyObjects, *pPubKeyObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    OS_CryptoLibKey_free(*pPubKeyObj, &self->memIf);

    return err;
}

static seos_err_t
Key_free(
    void*              ctx,
    OS_CryptoLibKey_t* keyObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, keyObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PtrVector_remove(&self->keyObjects, keyObj);

    return OS_CryptoLibKey_free(keyObj, &self->memIf);
}

static seos_err_t
Key_exists(
    void*                    ctx,
    const OS_CryptoLibKey_t* keyObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->keyObjects, keyObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SEOS_SUCCESS;
}

static seos_err_t
Key_export(
    void*                    ctx,
    const OS_CryptoLibKey_t* keyObj,
    OS_CryptoKey_Data_t*     keyData)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->keyObjects, keyObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibKey_export(keyObj, keyData);
}

static seos_err_t
Key_getParams(
    void*                    ctx,
    const OS_CryptoLibKey_t* keyObj,
    void*                    keyParams,
    size_t*                  paramSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->keyObjects, keyObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibKey_getParams(keyObj, keyParams, paramSize);
}

static seos_err_t
Key_getAttribs(
    void*                    ctx,
    const OS_CryptoLibKey_t* keyObj,
    OS_CryptoKey_Attrib_t*   attribs)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->keyObjects, keyObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibKey_getAttribs(keyObj, attribs);
}

static seos_err_t
Key_loadParams(
    void*                      ctx,
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    if (NULL == ctx || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return OS_CryptoLibKey_loadParams(name, keyParams, paramSize);
}

// ------------------------------ Cipher API -----------------------------------

static seos_err_t
Cipher_init(
    void*                       ctx,
    OS_CryptoLibCipher_t**      pCipherObj,
    const OS_CryptoCipher_Alg_t algorithm,
    const OS_CryptoLibKey_t*    key,
    const void*                 iv,
    const size_t                ivSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == pCipherObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (ivSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, key))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = OS_CryptoLibCipher_init(pCipherObj, &self->memIf, algorithm, key,
                                       iv, ivSize)) != SEOS_SUCCESS)
    {
        return err;
    }

    if ((err = PtrVector_add(&self->cipherObjects, *pCipherObj)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    OS_CryptoLibCipher_free(*pCipherObj, &self->memIf);

    return err;
}

static seos_err_t
Cipher_free(
    void*                 ctx,
    OS_CryptoLibCipher_t* cipherObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->cipherObjects, cipherObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    PtrVector_remove(&self->cipherObjects, cipherObj);

    return OS_CryptoLibCipher_free(cipherObj, &self->memIf);
}

static seos_err_t
Cipher_exists(
    void*                       ctx,
    const OS_CryptoLibCipher_t* cipherObj)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->cipherObjects, cipherObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SEOS_SUCCESS;
}

static seos_err_t
Cipher_process(
    void*                 ctx,
    OS_CryptoLibCipher_t* cipherObj,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == input || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > OS_CryptoLib_SIZE_BUFFER ||
             *outputSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping input/output buffers
    memcpy(self->buffer, input, inputSize);
    return !PtrVector_hasPtr(&self->cipherObjects, cipherObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibCipher_process(cipherObj, self->buffer, inputSize, output,
                                      outputSize);
}

static seos_err_t
Cipher_start(
    void*                 ctx,
    OS_CryptoLibCipher_t* cipherObj,
    const void*           ad,
    const size_t          adSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (adSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->cipherObjects, cipherObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibCipher_start(cipherObj, ad, adSize);
}

static seos_err_t
Cipher_finalize(
    void*                 ctx,
    OS_CryptoLibCipher_t* cipherObj,
    void*                 output,
    size_t*               outputSize)
{
    OS_CryptoLib_t* self = (OS_CryptoLib_t*) ctx;

    if (NULL == ctx || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*outputSize > OS_CryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->cipherObjects, cipherObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           OS_CryptoLibCipher_finalize(cipherObj, output, outputSize);
}

// ------------------------------- init/free -----------------------------------

static const OS_CryptoImpl_Vtable_t OS_CryptoLib_vtable =
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
OS_CryptoLib_init(
    OS_CryptoImpl_t*             impl,
    const OS_Crypto_Memory_t*    memIf,
    const OS_CryptoLib_Config_t* cfg)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    OS_CryptoLib_t* self;

    if (NULL == impl || NULL == memIf || NULL == cfg || NULL == cfg->rng.entropy)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((self = memIf->malloc(sizeof(OS_CryptoLib_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    impl->context = self;
    impl->vtable  = &OS_CryptoLib_vtable;
    self->memIf   = *memIf;

    if ((err = PtrVector_init(&self->digestObjects)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_init(&self->macObjects)) != SEOS_SUCCESS)
    {
        goto err1;
    }
    else if ((err = PtrVector_init(&self->keyObjects)) != SEOS_SUCCESS)
    {
        goto err2;
    }
    else if ((err = PtrVector_init(&self->cipherObjects) != SEOS_SUCCESS))
    {
        goto err3;
    }
    else if ((err = PtrVector_init(&self->signatureObjects) != SEOS_SUCCESS))
    {
        goto err4;
    }
    else if ((err = PtrVector_init(&self->agreementObjects) != SEOS_SUCCESS))
    {
        goto err5;
    }

    if ((err = OS_CryptoLibRng_init(&self->rng, &self->memIf,
                                    (const OS_CryptoRng_Entropy_func*)
                                    cfg->rng.entropy, cfg->rng.context)) != SEOS_SUCCESS)
    {
        goto err6;
    }

    return SEOS_SUCCESS;

err6:
    PtrVector_free(&self->agreementObjects);
err5:
    PtrVector_free(&self->signatureObjects);
err4:
    PtrVector_free(&self->cipherObjects);
err3:
    PtrVector_free(&self->keyObjects);
err2:
    PtrVector_free(&self->macObjects);
err1:
    PtrVector_free(&self->digestObjects);
err0:
    memIf->free(self);

    return err;
}

seos_err_t
OS_CryptoLib_free(
    OS_CryptoLib_t* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    OS_CryptoLibRng_free(self->rng, &self->memIf);

    PtrVector_free(&self->agreementObjects);
    PtrVector_free(&self->signatureObjects);
    PtrVector_free(&self->cipherObjects);
    PtrVector_free(&self->keyObjects);
    PtrVector_free(&self->macObjects);
    PtrVector_free(&self->digestObjects);

    self->memIf.free(self);

    return SEOS_SUCCESS;
}