/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Cipher.h"
#include "lib/SeosCryptoKey.h"
#include "lib/SeosCryptoRng.h"
#include "lib/SeosCryptoLib_Digest.h"
#include "lib/SeosCryptoLib_Mac.h"
#include "lib/SeosCryptoLib_Signature.h"
#include "lib/SeosCryptoLib_Agreement.h"

#include "SeosCryptoLib.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private static functions ----------------------------------------------------

// -1 = not found
static size_t
SeosCryptoLib_findHandle(
    PointerVector* v, Pointer handle)
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

seos_err_t
SeosCryptoLib_Rng_getBytes(
    SeosCryptoApi_Context*       api,
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

seos_err_t
SeosCryptoLib_Rng_reseed(
    SeosCryptoApi_Context* api,
    const void*            seed,
    const size_t           seedLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRng_reSeed(&self->cryptoRng, seed, seedLen);
}

// -------------------------------- MAC API ------------------------------------

seos_err_t
SeosCryptoLib_Mac_init(
    SeosCryptoApi_Context*      api,
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

seos_err_t
SeosCryptoLib_Mac_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj)
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

seos_err_t
SeosCryptoLib_Mac_start(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj,
    const void*            secret,
    const size_t           secretSize)
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

seos_err_t
SeosCryptoLib_Mac_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj,
    const void*            data,
    const size_t           dataLen)
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

seos_err_t
SeosCryptoLib_Mac_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Mac*     macObj,
    void*                  mac,
    size_t*                macSize)
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

seos_err_t
SeosCryptoLib_Digest_init(
    SeosCryptoApi_Context*         api,
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

seos_err_t
SeosCryptoLib_Digest_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digObj)
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

seos_err_t
SeosCryptoLib_Digest_clone(
    SeosCryptoApi_Context*      api,
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

seos_err_t
SeosCryptoLib_Digest_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digObj,
    const void*            data,
    const size_t           dataLen)
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

seos_err_t
SeosCryptoLib_Digest_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Digest*  digObj,
    void*                  digest,
    size_t*                digestSize)
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

seos_err_t
SeosCryptoLib_Signature_init(
    SeosCryptoApi_Context*            api,
    SeosCryptoLib_Signature**         pSigObj,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoApi_Key           prvHandle,
    const SeosCryptoApi_Key           pubHandle)
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
                                           digest, prvHandle, pubHandle)) != SEOS_SUCCESS)
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

seos_err_t
SeosCryptoLib_Signature_free(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Signature* sigObj)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->signatureHandleVector, sigObj)) != -1)
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

seos_err_t
SeosCryptoLib_Signature_sign(
    SeosCryptoApi_Context*   api,
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

seos_err_t
SeosCryptoLib_Signature_verify(
    SeosCryptoApi_Context*   api,
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

seos_err_t
SeosCryptoLib_Agreement_init(
    SeosCryptoApi_Context*            api,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoApi_Key           prvKey)
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

seos_err_t
SeosCryptoLib_Agreement_free(
    SeosCryptoApi_Context*   api,
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

seos_err_t
SeosCryptoLib_Agreement_agree(
    SeosCryptoApi_Context*   api,
    SeosCryptoLib_Agreement* agrObj,
    const SeosCryptoApi_Key  pubKey,
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
seos_err_t
SeosCryptoLib_Key_generate(
    SeosCryptoApi_Context*        api,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pKeyHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, *pKeyHandle) != -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pKeyHandle = self->memIf.malloc(sizeof(SeosCryptoKey))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    retval = SeosCryptoKey_generate(*pKeyHandle, &self->memIf, &self->cryptoRng,
                                    spec);
    if (retval != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->keyHandleVector, *pKeyHandle))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoKey_free(*pKeyHandle, &self->memIf);
err0:
    self->memIf.free(*pKeyHandle);
    return retval;
}

seos_err_t
SeosCryptoLib_Key_makePublic(
    SeosCryptoApi_Context*           api,
    SeosCryptoApi_Key*               pPubKeyHandle,
    const SeosCryptoApi_Key          prvKeyHandle,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pPubKeyHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, *pPubKeyHandle) != -1
             ||
             SeosCryptoLib_findHandle(&self->keyHandleVector, prvKeyHandle) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pPubKeyHandle = self->memIf.malloc(sizeof(SeosCryptoKey))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    retval = SeosCryptoKey_makePublic(*pPubKeyHandle, &self->memIf, prvKeyHandle,
                                      attribs);
    if (retval != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->keyHandleVector, *pPubKeyHandle))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoKey_free(*pPubKeyHandle, &self->memIf);
err0:
    self->memIf.free(*pPubKeyHandle);
    return retval;
}

seos_err_t
SeosCryptoLib_Key_import(
    SeosCryptoApi_Context*        api,
    SeosCryptoApi_Key*            pKeyHandle,
    const SeosCryptoApi_Key       wrapKeyHandle,
    const SeosCryptoApi_Key_Data* keyData)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pKeyHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, *pKeyHandle) != -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if (NULL != wrapKeyHandle &&
             (SeosCryptoLib_findHandle(&self->keyHandleVector, wrapKeyHandle) == -1))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pKeyHandle = self->memIf.malloc(sizeof(SeosCryptoKey))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    retval = SeosCryptoKey_import(*pKeyHandle, &self->memIf, wrapKeyHandle,
                                  keyData);
    if (retval != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->keyHandleVector, *pKeyHandle))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoKey_free(*pKeyHandle, &self->memIf);
err0:
    self->memIf.free(*pKeyHandle);
    return retval;
}

seos_err_t
SeosCryptoLib_Key_export(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Key keyHandle,
    const SeosCryptoApi_Key wrapKeyHandle,
    SeosCryptoApi_Key_Data* keyData)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == wrapKeyHandle)
    {
        return (SeosCryptoLib_findHandle(&self->keyHandleVector, keyHandle) == -1) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_export(keyHandle, wrapKeyHandle, keyData);
    }
    else
    {
        return ((SeosCryptoLib_findHandle(&self->keyHandleVector, keyHandle) == -1)
                || (SeosCryptoLib_findHandle(&self->keyHandleVector, wrapKeyHandle) == -1)) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_export(keyHandle, wrapKeyHandle, keyData);
    }
}

seos_err_t
SeosCryptoLib_Key_getParams(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Key keyHandle,
    void*                   keyParams,
    size_t*                 paramSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->keyHandleVector, keyHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoKey_getParams(keyHandle, keyParams, paramSize);
}

seos_err_t
SeosCryptoLib_Key_loadParams(
    SeosCryptoApi_Context*        api,
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

seos_err_t
SeosCryptoLib_Key_free(
    SeosCryptoApi_Context*  api,
    const SeosCryptoApi_Key keyHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    handlePos = SeosCryptoLib_findHandle(&self->keyHandleVector, keyHandle);
    if (-1 != handlePos)
    {
        retval = SeosCryptoKey_free(keyHandle, &self->memIf);
        if (SEOS_SUCCESS == retval)
        {
            SeosCryptoLib_removeHandle(&self->keyHandleVector, handlePos);
            self->memIf.free(keyHandle);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

// ------------------------------ Cipher API -----------------------------------

seos_err_t
SeosCryptoLib_Cipher_init(
    SeosCryptoApi_Context*         api,
    SeosCryptoLib_Cipher**         pCipherObj,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoApi_Key        key,
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

seos_err_t
SeosCryptoLib_Cipher_free(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj)
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

seos_err_t
SeosCryptoLib_Cipher_process(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    const void*            input,
    const size_t           inputSize,
    void*                  output,
    size_t*                outputSize)
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

seos_err_t
SeosCryptoLib_Cipher_start(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    const void*            input,
    const size_t           inputSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->cipherHandleVector,
                                     cipherObj) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_start(cipherObj, input, inputSize);
}

seos_err_t
SeosCryptoLib_Cipher_finalize(
    SeosCryptoApi_Context* api,
    SeosCryptoLib_Cipher*  cipherObj,
    void*                  buf,
    size_t*                bufSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->cipherHandleVector,
                                     cipherObj) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_finalize(cipherObj, buf, bufSize);
}

// ---------------------------- API Management ---------------------------------

static const SeosCryptoApi_Vtable SeosCryptoLib_vtable =
{
    .Rng_getBytes        = SeosCryptoLib_Rng_getBytes,
    .Rng_reseed          = SeosCryptoLib_Rng_reseed,
    .Mac_init            = SeosCryptoLib_Mac_init,
    .Mac_free            = SeosCryptoLib_Mac_free,
    .Mac_start           = SeosCryptoLib_Mac_start,
    .Mac_process         = SeosCryptoLib_Mac_process,
    .Mac_finalize        = SeosCryptoLib_Mac_finalize,
    .Digest_init         = SeosCryptoLib_Digest_init,
    .Digest_free         = SeosCryptoLib_Digest_free,
    .Digest_clone        = SeosCryptoLib_Digest_clone,
    .Digest_process      = SeosCryptoLib_Digest_process,
    .Digest_finalize     = SeosCryptoLib_Digest_finalize,
    .Key_generate        = SeosCryptoLib_Key_generate,
    .Key_makePublic      = SeosCryptoLib_Key_makePublic,
    .Key_import          = SeosCryptoLib_Key_import,
    .Key_export          = SeosCryptoLib_Key_export,
    .Key_getParams       = SeosCryptoLib_Key_getParams,
    .Key_loadParams      = SeosCryptoLib_Key_loadParams,
    .Key_free            = SeosCryptoLib_Key_free,
    .Signature_init      = SeosCryptoLib_Signature_init,
    .Signature_free      = SeosCryptoLib_Signature_free,
    .Signature_sign      = SeosCryptoLib_Signature_sign,
    .Signature_verify    = SeosCryptoLib_Signature_verify,
    .Agreement_init      = SeosCryptoLib_Agreement_init,
    .Agreement_free      = SeosCryptoLib_Agreement_free,
    .Agreement_agree     = SeosCryptoLib_Agreement_agree,
    .Cipher_init         = SeosCryptoLib_Cipher_init,
    .Cipher_free         = SeosCryptoLib_Cipher_free,
    .Cipher_process      = SeosCryptoLib_Cipher_process,
    .Cipher_start        = SeosCryptoLib_Cipher_start,
    .Cipher_finalize     = SeosCryptoLib_Cipher_finalize,
    .free                = SeosCryptoLib_free
};

seos_err_t
SeosCryptoLib_init(
    SeosCryptoLib*                 self,
    const SeosCryptoApi_Callbacks* cbFuncs,
    void*                          entropyCtx)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == cbFuncs || NULL == cbFuncs->free
        || NULL == cbFuncs->malloc || NULL == cbFuncs->entropy)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->parent.vtable = &SeosCryptoLib_vtable;
    self->memIf.malloc  = cbFuncs->malloc;
    self->memIf.free    = cbFuncs->free;

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
                                     (const SeosCryptoApi_Rng_EntropyFunc*) cbFuncs->entropy,
                                     entropyCtx)) != SEOS_SUCCESS)
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
    SeosCryptoApi_Context* api)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    SeosCryptoRng_free(&self->cryptoRng, &self->memIf);

    PointerVector_dtor(&self->agreementHandleVector);
    PointerVector_dtor(&self->signatureHandleVector);
    PointerVector_dtor(&self->cipherHandleVector);
    PointerVector_dtor(&self->keyHandleVector);
    PointerVector_dtor(&self->macHandleVector);
    PointerVector_dtor(&self->digestHandleVector);

    return SEOS_SUCCESS;
}