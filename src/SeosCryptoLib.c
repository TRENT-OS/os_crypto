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
findObject(
    PointerVector* v,
    const void*    obj)
{
    size_t vectorSize = PointerVector_getSize(v);

    for (size_t i = 0; i < vectorSize; i++)
    {
        if (obj == PointerVector_getElementAt(v, i))
        {
            return i;
        }
    }
    return -1;
}

static bool
hasObject(
    PointerVector* v,
    const void*    obj)
{
    return (obj == NULL) ? false : findObject(v, obj) != -1;
}

static void
removeObject(
    PointerVector* v,
    size_t         pos)
{
    PointerVector_replaceElementAt(v, pos, PointerVector_getBack(v));
    PointerVector_popBack(v);
}

static seos_err_t
addObject(
    PointerVector* v,
    void*          obj)
{
    return !PointerVector_pushBack(v, obj) ?
           SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_SUCCESS;
}

static void
freeObjectList(
    PointerVector* v)
{
    PointerVector_dtor(v);
}

static seos_err_t
createObjectList(
    PointerVector* v)
{
    return !PointerVector_ctor(v, 1) ? SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_SUCCESS;
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

    return SeosCryptoLib_Rng_getBytes(&self->cryptoRng, flags, buf, bufLen);
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

    return SeosCryptoLib_Rng_reSeed(&self->cryptoRng, seed, seedLen);
}

// -------------------------------- MAC API ------------------------------------

static seos_err_t
Mac_init(
    SeosCryptoApi*              api,
    SeosCryptoLib_Mac**         pMacObj,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pMacObj)
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
    else if ((err = addObject(&self->macObjects, *pMacObj)) != SEOS_SUCCESS)
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
    SeosCryptoApi*     api,
    SeosCryptoLib_Mac* macObj)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t pos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((pos = findObject(&self->macObjects, macObj)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Mac_free(macObj, &self->memIf)) == SEOS_SUCCESS)
    {
        removeObject(&self->macObjects, pos);
        self->memIf.free(macObj);
    }

    return err;
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

    return !hasObject(&self->macObjects, macObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_start(macObj, secret, secretSize);
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

    return !hasObject(&self->macObjects, macObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_process(macObj, data, dataLen);
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

    return !hasObject(&self->macObjects, macObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Mac_finalize(macObj, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

static seos_err_t
Digest_init(
    SeosCryptoApi*                 api,
    SeosCryptoLib_Digest**         pDigObj,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pDigObj)
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
    else if ((err = addObject(&self->digestObjects, *pDigObj)) != SEOS_SUCCESS)
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
    SeosCryptoApi*        api,
    SeosCryptoLib_Digest* digObj)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t pos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((pos = findObject(&self->digestObjects, digObj)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Digest_free(digObj, &self->memIf)) == SEOS_SUCCESS)
    {
        removeObject(&self->digestObjects, pos);
        self->memIf.free(digObj);
    }

    return err;
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

    return !hasObject(&self->digestObjects, dstDigObj) ||
           !hasObject(&self->digestObjects, srcDigObj) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_clone(dstDigObj, srcDigObj);
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

    return !hasObject(&self->digestObjects, digObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_process(digObj, data, dataLen);
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

    return !hasObject(&self->digestObjects, digObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Digest_finalize(digObj, digest, digestSize);
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
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pSigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((*pSigObj = self->memIf.malloc(sizeof(SeosCryptoLib_Signature))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Signature_init(*pSigObj, &self->memIf, algorithm,
                                            digest, prvKey, pubKey)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = addObject(&self->signatureObjects, *pSigObj)) != SEOS_SUCCESS)
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
    SeosCryptoApi*           api,
    SeosCryptoLib_Signature* sigObj)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t pos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((pos = findObject(&self->signatureObjects, sigObj)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Signature_free(sigObj, &self->memIf)) == SEOS_SUCCESS)
    {
        removeObject(&self->signatureObjects, pos);
        self->memIf.free(sigObj);
    }

    return err;
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
    return !hasObject(&self->signatureObjects, sigObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_sign(sigObj, &self->cryptoRng, self->buffer,
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

    return !hasObject(&self->signatureObjects, sigObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Signature_verify(sigObj, &self->cryptoRng, hash, hashSize,
                                          signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    SeosCryptoApi*                    api,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pAgrObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!hasObject(&self->keyObjects, prvKey))
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
    else if ((err = addObject(&self->agreementObjects,
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
    SeosCryptoApi*           api,
    SeosCryptoLib_Agreement* agrObj)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t pos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((pos = findObject(&self->agreementObjects, agrObj)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Agreement_free(agrObj, &self->memIf)) == SEOS_SUCCESS)
    {
        removeObject(&self->agreementObjects, pos);
        self->memIf.free(agrObj);
    }

    return err;
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

    return !hasObject(&self->agreementObjects, agrObj) ||
           !hasObject(&self->keyObjects, pubKey) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Agreement_agree(agrObj, &self->cryptoRng, pubKey, shared,
                                         sharedSize);
}

// -------------------------------- Key API ------------------------------------

static seos_err_t
Key_generate(
    SeosCryptoApi*                api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pKeyObj)
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
    else if ((err = addObject(&self->keyObjects, *pKeyObj)) != SEOS_SUCCESS)
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
    SeosCryptoApi*                api,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoLib_Key*      wrapKeyObj,
    const SeosCryptoApi_Key_Data* keyData)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL != wrapKeyObj && !hasObject(&self->keyObjects, wrapKeyObj))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pKeyObj = self->memIf.malloc(sizeof(SeosCryptoLib_Key))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Key_import(*pKeyObj, &self->memIf, wrapKeyObj,
                                        keyData)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = addObject(&self->keyObjects, *pKeyObj)) != SEOS_SUCCESS)
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
    SeosCryptoApi*                   api,
    SeosCryptoLib_Key**              pPubKeyObj,
    const SeosCryptoLib_Key*         prvKeyObj,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pPubKeyObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!hasObject(&self->keyObjects, prvKeyObj))
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
    else if ((err = addObject(&self->keyObjects, *pPubKeyObj)) != SEOS_SUCCESS)
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
    else if (NULL != wrapKeyObj && (!hasObject(&self->keyObjects, wrapKeyObj)))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    return !hasObject(&self->keyObjects, keyObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_export(keyObj, wrapKeyObj, keyData);
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

    return !hasObject(&self->keyObjects, keyObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Key_getParams(keyObj, keyParams, paramSize);
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

    return SeosCryptoLib_Key_loadParams(name, keyParams, paramSize);
}

static seos_err_t
Key_free(
    SeosCryptoApi*     api,
    SeosCryptoLib_Key* keyObj)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t pos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((pos = findObject(&self->keyObjects, keyObj)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Key_free(keyObj, &self->memIf)) == SEOS_SUCCESS)
    {
        removeObject(&self->keyObjects, pos);
        self->memIf.free(keyObj);
    }

    return err;
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
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || NULL == pCipherObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!hasObject(&self->keyObjects, key))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pCipherObj = self->memIf.malloc(sizeof(SeosCryptoLib_Cipher))) ==  NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoLib_Cipher_init(*pCipherObj, &self->memIf, algorithm, key,
                                         iv, ivLen)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = addObject(&self->cipherObjects,
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
    SeosCryptoApi*        api,
    SeosCryptoLib_Cipher* cipherObj)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t pos;

    if (NULL == api)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((pos = findObject(&self->cipherObjects, cipherObj)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((err = SeosCryptoLib_Cipher_free(cipherObj, &self->memIf)) == SEOS_SUCCESS)
    {
        removeObject(&self->cipherObjects, pos);
        self->memIf.free(cipherObj);
    }

    return err;
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
    return !hasObject(&self->cipherObjects, cipherObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_process(cipherObj, self->buffer, inputSize, output,
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

    return !hasObject(&self->cipherObjects, cipherObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_start(cipherObj, input, inputSize);
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

    return !hasObject(&self->cipherObjects, cipherObj) ? SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoLib_Cipher_finalize(cipherObj, buf, bufSize);
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

    if ((err = createObjectList(&self->digestObjects)) != SEOS_SUCCESS)
    {
        return err;
    }
    else if ((err = createObjectList(&self->macObjects)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if ((err = createObjectList(&self->keyObjects)) != SEOS_SUCCESS)
    {
        goto err1;
    }
    else if ((err = createObjectList(&self->cipherObjects) != SEOS_SUCCESS))
    {
        goto err2;
    }
    else if ((err = createObjectList(&self->signatureObjects) != SEOS_SUCCESS))
    {
        goto err3;
    }
    else if ((err = createObjectList(&self->agreementObjects) != SEOS_SUCCESS))
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
    freeObjectList(&self->agreementObjects);
err4:
    freeObjectList(&self->signatureObjects);
err3:
    freeObjectList(&self->cipherObjects);
err2:
    freeObjectList(&self->keyObjects);
err1:
    freeObjectList(&self->macObjects);
err0:
    freeObjectList(&self->digestObjects);

    return err;
}

seos_err_t
SeosCryptoLib_free(
    SeosCryptoLib* self)
{
    SeosCryptoLib_Rng_free(&self->cryptoRng, &self->memIf);

    freeObjectList(&self->agreementObjects);
    freeObjectList(&self->signatureObjects);
    freeObjectList(&self->cipherObjects);
    freeObjectList(&self->keyObjects);
    freeObjectList(&self->macObjects);
    freeObjectList(&self->digestObjects);

    return SEOS_SUCCESS;
}