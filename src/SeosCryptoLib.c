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

#include <string.h>

// Private static functions ----------------------------------------------------

// -1 = not found
static size_t
SeosCryptoLib_findHandle(
    PointerVector* v,
    const void*    handle)
{
    size_t vectorSize = PointerVector_getSize(v);

    for (size_t i = 0; i < vectorSize; i++)
    {
        if (handle == PointerVector_getElementAt(v, i))
        {
            return i;
        }
    }
    return -1;
}

static void
SeosCryptoLib_removeHandle(
    PointerVector* v, size_t pos)
{
    PointerVector_replaceElementAt(v, pos, PointerVector_getBack(v));
    PointerVector_popBack(v);
}

// -------------------------------- RNG API ------------------------------------

static seos_err_t
Rng_getBytes(
    SeosCryptoApi*               api,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRng_getBytes(&self->cryptoRng, flags, buf, bufLen);
}

static seos_err_t
Rng_reseed(
    SeosCryptoApi* api,
    const void*    seed,
    const size_t   seedLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRng_reSeed(&self->cryptoRng, seed, seedLen);
}

// -------------------------------- MAC API ------------------------------------

static seos_err_t
Mac_init(
    SeosCryptoApi*              api,
    SeosCryptoLib_Mac**         pMacObj,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pMacObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((*pMacObj = self->memIf.malloc(sizeof(SeosCryptoLib_Mac))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoMac_init(*pMacObj, &self->memIf,
                                     algorithm)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->macHandleVector, *pMacObj))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    SeosCryptoMac_free(*pMacObj, &self->memIf);
err0:
    self->memIf.free(*pMacObj);

    return retval;
}

static seos_err_t
Mac_free(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->macHandleVector,
                                              macObj)) != -1)
    {
        if ((retval = SeosCryptoMac_free(macObj, &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->macHandleVector, handlePos);
            self->memIf.free(macObj);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

static seos_err_t
Mac_start(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj,
    const void*        secret,
    const size_t       secretSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->macHandleVector, macObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoMac_start(macObj, secret, secretSize);
}

static seos_err_t
Mac_process(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj,
    const void*        data,
    const size_t       dataLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->macHandleVector, macObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoMac_process(macObj, data, dataLen);
}

static seos_err_t
Mac_finalize(
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj,
    void*              mac,
    size_t*            macSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->macHandleVector, macObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoMac_finalize(macObj, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

static seos_err_t
Digest_init(
    SeosCryptoApi*                 api,
    SeosCryptoLib_Digest**         pDigObj,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pDigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((*pDigObj = self->memIf.malloc(
                             sizeof(SeosCryptoLib_Digest))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoDigest_init(*pDigObj, &self->memIf,
                                        algorithm)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->digestHandleVector, *pDigObj))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    SeosCryptoDigest_free(*pDigObj, &self->memIf);
err0:
    self->memIf.free(*pDigObj);

    return retval;
}

static seos_err_t
Digest_free(
    SeosCryptoApi*        api,
    SeosCryptoLib_Digest* digObj)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->digestHandleVector,
                                              digObj)) != -1)
    {
        if ((retval = SeosCryptoDigest_free(digObj, &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->digestHandleVector, handlePos);
            self->memIf.free(digObj);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

static seos_err_t
Digest_clone(
    SeosCryptoApi*              api,
    SeosCryptoLib_Digest*       dstDigObj,
    const SeosCryptoLib_Digest* srcDigObj)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->digestHandleVector, dstDigObj) == -1 ||
           SeosCryptoLib_findHandle(&self->digestHandleVector, srcDigObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_clone(dstDigObj, srcDigObj);
}

static seos_err_t
Digest_process(
    SeosCryptoApi*        api,
    SeosCryptoLib_Digest* digObj,
    const void*           data,
    const size_t          dataLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->digestHandleVector, digObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_process(digObj, data, dataLen);
}

static seos_err_t
Digest_finalize(
    SeosCryptoApi*        api,
    SeosCryptoLib_Digest* digObj,
    void*                 digest,
    size_t*               digestSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->digestHandleVector, digObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_finalize(digObj, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

static seos_err_t
Signature_init(
    SeosCryptoApi*                    api,
    SeosCryptoLib_Signature**         pSigObj,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pSigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((*pSigObj = self->memIf.malloc(sizeof(SeosCryptoLib_Signature))) ==
             NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoSignature_init(*pSigObj, &self->memIf, algorithm,
                                           digest, prvKey, pubKey)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->signatureHandleVector, *pSigObj))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    SeosCryptoSignature_free(*pSigObj, &self->memIf);
err0:
    self->memIf.free(*pSigObj);

    return retval;
}

static seos_err_t
Signature_free(
    SeosCryptoApi*           api,
    SeosCryptoLib_Signature* sigObj)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->signatureHandleVector,
                                              sigObj)) != -1)
    {
        if ((retval = SeosCryptoSignature_free(sigObj, &self->memIf)) != SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->signatureHandleVector, handlePos);
            self->memIf.free(sigObj);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

static seos_err_t
Signature_sign(
    SeosCryptoApi*           api,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == hash)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping hash/signature buffers
    memcpy(self->buffer, hash, hashSize);
    return SeosCryptoLib_findHandle(&self->signatureHandleVector, sigObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoSignature_sign(sigObj, &self->cryptoRng, self->buffer,
                                    hashSize, signature, signatureSize);
}

static seos_err_t
Signature_verify(
    SeosCryptoApi*           api,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->signatureHandleVector, sigObj) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoSignature_verify(sigObj, &self->cryptoRng, hash, hashSize, signature,
                                      signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    SeosCryptoApi*                    api,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pAgrObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, prvKey) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if ((*pAgrObj = self->memIf.malloc(
                             sizeof(SeosCryptoLib_Agreement))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoAgreement_init(*pAgrObj, &self->memIf, algorithm,
                                           prvKey)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->agreementHandleVector, *pAgrObj))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoAgreement_free(*pAgrObj, &self->memIf);
err0:
    self->memIf.free(*pAgrObj);
    return retval;
}

static seos_err_t
Agreement_free(
    SeosCryptoApi*           api,
    SeosCryptoLib_Agreement* agrObj)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if ((handlePos = SeosCryptoLib_findHandle(&self->agreementHandleVector,
                                              agrObj)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((retval = SeosCryptoAgreement_free(agrObj, &self->memIf)) != SEOS_SUCCESS)
    {
        SeosCryptoLib_removeHandle(&self->agreementHandleVector, handlePos);
        self->memIf.free(agrObj);
    }

    return retval;
}

static seos_err_t
Agreement_agree(
    SeosCryptoApi*           api,
    SeosCryptoLib_Agreement* agrObj,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->agreementHandleVector, agrObj) == -1)
           || (SeosCryptoLib_findHandle(&self->keyHandleVector, pubKey) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoAgreement_agree(agrObj, &self->cryptoRng, pubKey, shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

static seos_err_t
Key_generate(
    SeosCryptoApi*                api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, *pKeyObj) != -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pKeyObj = self->memIf.malloc(sizeof(SeosCryptoLib_Key))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    retval = SeosCryptoKey_generate(*pKeyObj, &self->memIf, &self->cryptoRng, spec);
    if (retval != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->keyHandleVector, *pKeyObj))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoKey_free(*pKeyObj, &self->memIf);
err0:
    self->memIf.free(*pKeyObj);
    return retval;
}

static seos_err_t
Key_import(
    SeosCryptoApi*                api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoLib_Key*      wrapKeyObj,
    const SeosCryptoApi_Key_Data* keyData)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, *pKeyObj) != -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (NULL != wrapKeyObj &&
             (SeosCryptoLib_findHandle(&self->keyHandleVector, wrapKeyObj) == -1))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pKeyObj = self->memIf.malloc(sizeof(SeosCryptoLib_Key))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoKey_import(*pKeyObj, &self->memIf, wrapKeyObj,
                                       keyData)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->keyHandleVector, *pKeyObj))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoKey_free(*pKeyObj, &self->memIf);
err0:
    self->memIf.free(*pKeyObj);
    return retval;
}

static seos_err_t
Key_makePublic(
    SeosCryptoApi*                   api,
    SeosCryptoLib_Key**              pPubKeyObj,
    const SeosCryptoLib_Key*         prvKeyObj,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pPubKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, *pPubKeyObj) != -1 ||
             SeosCryptoLib_findHandle(&self->keyHandleVector, prvKeyObj) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pPubKeyObj = self->memIf.malloc(sizeof(SeosCryptoLib_Key))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    retval = SeosCryptoKey_makePublic(*pPubKeyObj, &self->memIf, prvKeyObj,
                                      attribs);
    if (retval != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->keyHandleVector, *pPubKeyObj))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoKey_free(*pPubKeyObj, &self->memIf);
err0:
    self->memIf.free(*pPubKeyObj);
    return retval;
}

static seos_err_t
Key_export(
    SeosCryptoApi*           api,
    const SeosCryptoLib_Key* keyObj,
    const SeosCryptoLib_Key* wrapKeyObj,
    SeosCryptoApi_Key_Data*  keyData)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == wrapKeyObj)
    {
        return (SeosCryptoLib_findHandle(&self->keyHandleVector, keyObj) == -1) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_export(keyObj, wrapKeyObj, keyData);
    }
    else
    {
        return ((SeosCryptoLib_findHandle(&self->keyHandleVector, keyObj) == -1)
                || (SeosCryptoLib_findHandle(&self->keyHandleVector, wrapKeyObj) == -1)) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_export(keyObj, wrapKeyObj, keyData);
    }
}

static seos_err_t
Key_getParams(
    SeosCryptoApi*           api,
    const SeosCryptoLib_Key* keyObj,
    void*                    keyParams,
    size_t*                  paramSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->keyHandleVector, keyObj) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoKey_getParams(keyObj, keyParams, paramSize);
}

static seos_err_t
Key_loadParams(
    SeosCryptoApi*                api,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoKey_loadParams(name, keyParams, paramSize);
}

static seos_err_t
Key_free(
    SeosCryptoApi*     api,
    SeosCryptoLib_Key* keyObj)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->keyHandleVector,
                                              keyObj)) != -1)
    {
        if ((retval = SeosCryptoKey_free(keyObj, &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->keyHandleVector, handlePos);
            self->memIf.free(keyObj);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

// ------------------------------ Cipher API -----------------------------------

static seos_err_t
Cipher_init(
    SeosCryptoApi*                 api,
    SeosCryptoLib_Cipher**         pCipherObj,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       key,
    const void*                    iv,
    const size_t                   ivLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pCipherObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, key) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pCipherObj = self->memIf.malloc(sizeof(SeosCryptoLib_Cipher))) ==  NULL)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    else
    {
        if ((retval = SeosCryptoCipher_init(*pCipherObj, &self->memIf, algorithm, key,
                                            iv, ivLen)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        else if (!PointerVector_pushBack(&self->cipherHandleVector, *pCipherObj))
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err1;
        }
    }

    return retval;

err1:
    SeosCryptoCipher_free(*pCipherObj, &self->memIf);
err0:
    self->memIf.free(*pCipherObj);

    return retval;
}

static seos_err_t
Cipher_free(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->cipherHandleVector,
                                              cipherObj)) != -1)
    {
        if ((retval = SeosCryptoCipher_free(cipherObj, &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->cipherHandleVector, handlePos);
            self->memIf.free(cipherObj);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

static seos_err_t
Cipher_process(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == input)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping input/output buffers
    memcpy(self->buffer, input, inputSize);
    return (SeosCryptoLib_findHandle(&self->cipherHandleVector, cipherObj) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_process(cipherObj, self->buffer, inputSize, output,
                                    outputSize);
}

static seos_err_t
Cipher_start(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           input,
    const size_t          inputSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->cipherHandleVector, cipherObj) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_start(cipherObj, input, inputSize);
}

static seos_err_t
Cipher_finalize(
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj,
    void*                 buf,
    size_t*               bufSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->cipherHandleVector, cipherObj) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_finalize(cipherObj, buf, bufSize);
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
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == memIf || NULL == memIf->free
        || NULL == memIf->malloc || NULL == cfg || NULL == cfg->rng.entropy)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->memIf = *memIf;
    *vtable = &SeosCryptoLib_vtable;

    if (!PointerVector_ctor(&self->digestHandleVector, 1))
    {
        return SEOS_ERROR_ABORTED;
    }
    else if (!PointerVector_ctor(&self->macHandleVector, 1))
    {
        retval = SEOS_ERROR_ABORTED;
        goto err0;
    }
    else if (!PointerVector_ctor(&self->keyHandleVector, 1))
    {
        retval = SEOS_ERROR_ABORTED;
        goto err1;
    }
    else if (!PointerVector_ctor(&self->cipherHandleVector, 1))
    {
        retval = SEOS_ERROR_ABORTED;
        goto err2;
    }
    else if (!PointerVector_ctor(&self->signatureHandleVector, 1))
    {
        retval = SEOS_ERROR_ABORTED;
        goto err3;
    }
    else if (!PointerVector_ctor(&self->agreementHandleVector, 1))
    {
        retval = SEOS_ERROR_ABORTED;
        goto err4;
    }

    if ((retval = SeosCryptoRng_init(&self->cryptoRng, &self->memIf,
                                     (const SeosCryptoApi_Rng_EntropyFunc*)
                                     cfg->rng.entropy, cfg->rng.context)) != SEOS_SUCCESS)
    {
        goto err5;
    }

    return retval;

err5:
    PointerVector_dtor(&self->agreementHandleVector);
err4:
    PointerVector_dtor(&self->signatureHandleVector);
err3:
    PointerVector_dtor(&self->cipherHandleVector);
err2:
    PointerVector_dtor(&self->keyHandleVector);
err1:
    PointerVector_dtor(&self->macHandleVector);
err0:
    PointerVector_dtor(&self->digestHandleVector);

    return retval;
}

seos_err_t
SeosCryptoLib_free(
    SeosCryptoLib* self)
{
    SeosCryptoRng_free(&self->cryptoRng, &self->memIf);

    PointerVector_dtor(&self->agreementHandleVector);
    PointerVector_dtor(&self->signatureHandleVector);
    PointerVector_dtor(&self->cipherHandleVector);
    PointerVector_dtor(&self->keyHandleVector);
    PointerVector_dtor(&self->macHandleVector);
    PointerVector_dtor(&self->digestHandleVector);

    return SEOS_SUCCESS;
}