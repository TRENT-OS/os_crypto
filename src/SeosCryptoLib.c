/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Cipher.h"
#include "lib/SeosCryptoLib_Key.h"
#include "lib/SeosCryptoLib_Rng.h"
#include "lib/SeosCryptoLib_Digest.h"
#include "lib/SeosCryptoLib_Mac.h"
#include "lib/SeosCryptoLib_Signature.h"
#include "lib/SeosCryptoLib_Agreement.h"

#include "SeosCryptoVtable.h"
#include "SeosCryptoLib.h"

#include "LibDebug/Debug.h"
#include "util/PtrVector.h"

#include <string.h>

// -------------------------------- RNG API ------------------------------------

static seos_err_t
Rng_getBytes(
    void*                        ctx,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (bufSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return SeosCryptoLib_Rng_getBytes(&self->cryptoRng, flags, buf, bufSize);
}

static seos_err_t
Rng_reseed(
    void*        ctx,
    const void*  seed,
    const size_t seedSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (seedSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return SeosCryptoLib_Rng_reSeed(&self->cryptoRng, seed, seedSize);
}

// -------------------------------- MAC API ------------------------------------

static seos_err_t
Mac_init(
    void*                       ctx,
    SeosCryptoLib_Mac**         pMacObj,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pMacObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((*pMacObj = self->memIf.malloc(sizeof(SeosCryptoLib_Mac))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Mac_init(*pMacObj, &self->memIf,
                                      algorithm)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->macObjects, *pMacObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Mac_free(*pMacObj, &self->memIf);
err0:
    self->memIf.free(*pMacObj);

    return err;
}

static seos_err_t
Mac_free(
    void*              ctx,
    SeosCryptoLib_Mac* macObj)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!PtrVector_hasPtr(&self->macObjects, macObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Mac_free(macObj, &self->memIf)) == SEOS_SUCCESS)
    {
        PtrVector_remove(&self->macObjects, macObj);
        self->memIf.free(macObj);
    }

    return err;
}

static seos_err_t
Mac_start(
    void*              ctx,
    SeosCryptoLib_Mac* macObj,
    const void*        secret,
    const size_t       secretSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (secretSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->macObjects, macObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_start(macObj, secret, secretSize);
}

static seos_err_t
Mac_process(
    void*              ctx,
    SeosCryptoLib_Mac* macObj,
    const void*        data,
    const size_t       dataSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->macObjects, macObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_process(macObj, data, dataSize);
}

static seos_err_t
Mac_finalize(
    void*              ctx,
    SeosCryptoLib_Mac* macObj,
    void*              mac,
    size_t*            macSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == macSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*macSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->macObjects, macObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_finalize(macObj, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

static seos_err_t
Digest_init(
    void*                          ctx,
    SeosCryptoLib_Digest**         pDigObj,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pDigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((*pDigObj = self->memIf.malloc(sizeof(SeosCryptoLib_Digest))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Digest_init(*pDigObj, &self->memIf,
                                         algorithm)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->digestObjects, *pDigObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Digest_free(*pDigObj, &self->memIf);
err0:
    self->memIf.free(*pDigObj);

    return err;
}

static seos_err_t
Digest_free(
    void*                 ctx,
    SeosCryptoLib_Digest* digObj)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->digestObjects, digObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Digest_free(digObj, &self->memIf)) == SEOS_SUCCESS)
    {
        PtrVector_remove(&self->digestObjects, digObj);
        self->memIf.free(digObj);
    }

    return err;
}

static seos_err_t
Digest_clone(
    void*                       ctx,
    SeosCryptoLib_Digest*       dstDigObj,
    const SeosCryptoLib_Digest* srcDigObj)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->digestObjects, dstDigObj) ||
           !PtrVector_hasPtr(&self->digestObjects, srcDigObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_clone(dstDigObj, srcDigObj);
}

static seos_err_t
Digest_process(
    void*                 ctx,
    SeosCryptoLib_Digest* digObj,
    const void*           data,
    const size_t          dataSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->digestObjects, digObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_process(digObj, data, dataSize);
}

static seos_err_t
Digest_finalize(
    void*                 ctx,
    SeosCryptoLib_Digest* digObj,
    void*                 digest,
    size_t*               digestSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*digestSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->digestObjects, digObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_finalize(digObj, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

static seos_err_t
Signature_init(
    void*                             ctx,
    SeosCryptoLib_Signature**         pSigObj,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pSigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((*pSigObj = self->memIf.malloc(sizeof(SeosCryptoLib_Signature))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if (prvKey != NULL && !PtrVector_hasPtr(&self->keyObjects, prvKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (pubKey != NULL && !PtrVector_hasPtr(&self->keyObjects, pubKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Signature_init(*pSigObj, &self->memIf, algorithm,
                                            digest, prvKey, pubKey)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->signatureObjects,
                                  *pSigObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Signature_free(*pSigObj, &self->memIf);
err0:
    self->memIf.free(*pSigObj);

    return err;
}

static seos_err_t
Signature_free(
    void*                    ctx,
    SeosCryptoLib_Signature* sigObj)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->signatureObjects, sigObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Signature_free(sigObj, &self->memIf)) == SEOS_SUCCESS)
    {
        PtrVector_remove(&self->signatureObjects, sigObj);
        self->memIf.free(sigObj);
    }

    return err;
}

static seos_err_t
Signature_sign(
    void*                    ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == hash || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > SeosCryptoLib_SIZE_BUFFER ||
             *signatureSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping hash/signature buffers
    memcpy(self->buffer, hash, hashSize);
    return !PtrVector_hasPtr(&self->signatureObjects, sigObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_sign(sigObj, &self->cryptoRng, self->buffer,
                                        hashSize, signature, signatureSize);
}

static seos_err_t
Signature_verify(
    void*                    ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->signatureObjects, sigObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_verify(sigObj, &self->cryptoRng, hash, hashSize,
                                          signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    void*                             ctx,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pAgrObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, prvKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pAgrObj = self->memIf.malloc(sizeof(SeosCryptoLib_Agreement))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Agreement_init(*pAgrObj, &self->memIf, algorithm,
                                            prvKey)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->agreementObjects,
                                  *pAgrObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Agreement_free(*pAgrObj, &self->memIf);
err0:
    self->memIf.free(*pAgrObj);

    return err;
}

static seos_err_t
Agreement_free(
    void*                    ctx,
    SeosCryptoLib_Agreement* agrObj)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->agreementObjects, agrObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Agreement_free(agrObj, &self->memIf)) == SEOS_SUCCESS)
    {
        PtrVector_remove(&self->agreementObjects, agrObj);
        self->memIf.free(agrObj);
    }

    return err;
}

static seos_err_t
Agreement_agree(
    void*                    ctx,
    SeosCryptoLib_Agreement* agrObj,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*sharedSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, pubKey))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    return !PtrVector_hasPtr(&self->agreementObjects, agrObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Agreement_agree(agrObj, &self->cryptoRng, pubKey, shared,
                                         sharedSize);
}

// -------------------------------- Key API ------------------------------------

static seos_err_t
Key_generate(
    void*                         ctx,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((*pKeyObj = self->memIf.malloc(sizeof(SeosCryptoLib_Key))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Key_generate(*pKeyObj, &self->memIf, &self->cryptoRng,
                                          spec)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->keyObjects, *pKeyObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Key_free(*pKeyObj, &self->memIf);
err0:
    self->memIf.free(*pKeyObj);

    return err;
}

static seos_err_t
Key_import(
    void*                         ctx,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Data* keyData)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((*pKeyObj = self->memIf.malloc(sizeof(SeosCryptoLib_Key))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Key_import(*pKeyObj, &self->memIf,
                                        keyData)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->keyObjects, *pKeyObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Key_free(*pKeyObj, &self->memIf);
err0:
    self->memIf.free(*pKeyObj);

    return err;
}

static seos_err_t
Key_makePublic(
    void*                            ctx,
    SeosCryptoLib_Key**              pPubKeyObj,
    const SeosCryptoLib_Key*         prvKeyObj,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pPubKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, prvKeyObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pPubKeyObj = self->memIf.malloc(sizeof(SeosCryptoLib_Key))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Key_makePublic(*pPubKeyObj, &self->memIf, prvKeyObj,
                                            attribs)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->keyObjects, *pPubKeyObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Key_free(*pPubKeyObj, &self->memIf);
err0:
    self->memIf.free(*pPubKeyObj);

    return err;
}

static seos_err_t
Key_export(
    void*                    ctx,
    const SeosCryptoLib_Key* keyObj,
    SeosCryptoApi_Key_Data*  keyData)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return !PtrVector_hasPtr(&self->keyObjects, keyObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_export(keyObj, keyData);
}

static seos_err_t
Key_getParams(
    void*                    ctx,
    const SeosCryptoLib_Key* keyObj,
    void*                    keyParams,
    size_t*                  paramSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->keyObjects, keyObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_getParams(keyObj, keyParams, paramSize);
}

static seos_err_t
Key_loadParams(
    void*                         ctx,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    if (NULL == ctx || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return SeosCryptoLib_Key_loadParams(name, keyParams, paramSize);
}

static seos_err_t
Key_free(
    void*              ctx,
    SeosCryptoLib_Key* keyObj)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, keyObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Key_free(keyObj, &self->memIf)) == SEOS_SUCCESS)
    {
        PtrVector_remove(&self->keyObjects, keyObj);
        self->memIf.free(keyObj);
    }

    return err;
}

// ------------------------------ Cipher API -----------------------------------

static seos_err_t
Cipher_init(
    void*                          ctx,
    SeosCryptoLib_Cipher**         pCipherObj,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       key,
    const void*                    iv,
    const size_t                   ivSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == pCipherObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (ivSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if (!PtrVector_hasPtr(&self->keyObjects, key))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pCipherObj = self->memIf.malloc(sizeof(SeosCryptoLib_Cipher))) ==  NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Cipher_init(*pCipherObj, &self->memIf, algorithm, key,
                                         iv, ivSize)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_add(&self->cipherObjects,
                                  *pCipherObj)) != SEOS_SUCCESS)
    {
        goto err1;
    }

    return err;

err1:
    SeosCryptoLib_Cipher_free(*pCipherObj, &self->memIf);
err0:
    self->memIf.free(*pCipherObj);

    return err;
}

static seos_err_t
Cipher_free(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!PtrVector_hasPtr(&self->cipherObjects, cipherObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Cipher_free(cipherObj, &self->memIf)) == SEOS_SUCCESS)
    {
        PtrVector_remove(&self->cipherObjects, cipherObj);
        self->memIf.free(cipherObj);
    }

    return err;
}

static seos_err_t
Cipher_process(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == input || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > SeosCryptoLib_SIZE_BUFFER ||
             *outputSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping input/output buffers
    memcpy(self->buffer, input, inputSize);
    return !PtrVector_hasPtr(&self->cipherObjects, cipherObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_process(cipherObj, self->buffer, inputSize, output,
                                        outputSize);
}

static seos_err_t
Cipher_start(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           ad,
    const size_t          adSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (adSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->cipherObjects, cipherObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_start(cipherObj, ad, adSize);
}

static seos_err_t
Cipher_finalize(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj,
    void*                 output,
    size_t*               outputSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) ctx;

    if (NULL == ctx || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*outputSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return !PtrVector_hasPtr(&self->cipherObjects, cipherObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_finalize(cipherObj, output, outputSize);
}

// ------------------------------- init/free -----------------------------------

static const SeosCryptoVtable SeosCryptoLib_vtable =
{
    .Rng_getBytes        = Rng_getBytes,
    .Rng_reseed          = Rng_reseed,
    .Mac_init            = Mac_init,
    .Mac_free            = Mac_free,
    .Mac_start           = Mac_start,
    .Mac_process         = Mac_process,
    .Mac_finalize        = Mac_finalize,
    .Digest_init         = Digest_init,
    .Digest_free         = Digest_free,
    .Digest_clone        = Digest_clone,
    .Digest_process      = Digest_process,
    .Digest_finalize     = Digest_finalize,
    .Key_generate        = Key_generate,
    .Key_makePublic      = Key_makePublic,
    .Key_import          = Key_import,
    .Key_export          = Key_export,
    .Key_getParams       = Key_getParams,
    .Key_loadParams      = Key_loadParams,
    .Key_free            = Key_free,
    .Signature_init      = Signature_init,
    .Signature_free      = Signature_free,
    .Signature_sign      = Signature_sign,
    .Signature_verify    = Signature_verify,
    .Agreement_init      = Agreement_init,
    .Agreement_free      = Agreement_free,
    .Agreement_agree     = Agreement_agree,
    .Cipher_init         = Cipher_init,
    .Cipher_free         = Cipher_free,
    .Cipher_process      = Cipher_process,
    .Cipher_start        = Cipher_start,
    .Cipher_finalize     = Cipher_finalize,
};

seos_err_t
SeosCryptoLib_init(
    SeosCryptoLib*                  self,
    const SeosCryptoVtable**        vtable,
    const SeosCryptoApi_MemIf*      memIf,
    const SeosCryptoApi_Lib_Config* cfg)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == memIf || NULL == memIf->free
        || NULL == memIf->malloc || NULL == cfg || NULL == cfg->rng.entropy)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->memIf = *memIf;
    *vtable = &SeosCryptoLib_vtable;

    if ((err = PtrVector_init(&self->digestObjects)) != SEOS_SUCCESS)
    {
        return err;
    }
    else if ((err = PtrVector_init(&self->macObjects)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = PtrVector_init(&self->keyObjects)) != SEOS_SUCCESS)
    {
        goto err1;
    }
    else if ((err = PtrVector_init(&self->cipherObjects) != SEOS_SUCCESS))
    {
        goto err2;
    }
    else if ((err = PtrVector_init(&self->signatureObjects) != SEOS_SUCCESS))
    {
        goto err3;
    }
    else if ((err = PtrVector_init(&self->agreementObjects) != SEOS_SUCCESS))
    {
        goto err4;
    }

    if ((err = SeosCryptoLib_Rng_init(&self->cryptoRng, &self->memIf,
                                      (const SeosCryptoApi_Rng_EntropyFunc*)
                                      cfg->rng.entropy, cfg->rng.context)) != SEOS_SUCCESS)
    {
        goto err5;
    }

    return err;

err5:
    PtrVector_free(&self->agreementObjects);
err4:
    PtrVector_free(&self->signatureObjects);
err3:
    PtrVector_free(&self->cipherObjects);
err2:
    PtrVector_free(&self->keyObjects);
err1:
    PtrVector_free(&self->macObjects);
err0:
    PtrVector_free(&self->digestObjects);

    return err;
}

seos_err_t
SeosCryptoLib_free(
    SeosCryptoLib* self)
{
    SeosCryptoLib_Rng_free(&self->cryptoRng, &self->memIf);

    PtrVector_free(&self->agreementObjects);
    PtrVector_free(&self->signatureObjects);
    PtrVector_free(&self->cipherObjects);
    PtrVector_free(&self->keyObjects);
    PtrVector_free(&self->macObjects);
    PtrVector_free(&self->digestObjects);

    return SEOS_SUCCESS;
}