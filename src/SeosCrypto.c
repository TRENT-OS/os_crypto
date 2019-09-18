/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoCipher.h"
#include "SeosCryptoKey.h"
#include "SeosCryptoRng.h"
#include "SeosCryptoDigest.h"
#include "SeosCryptoSignature.h"
#include "SeosCryptoAgreement.h"
#include "SeosCrypto.h"

#include "LibDebug/Debug.h"

static const SeosCryptoCtx_Vtable SeosCrypto_vtable =
{
    .rngGetBytes            = SeosCrypto_rngGetBytes,
    .rngReSeed              = SeosCrypto_rngReSeed,
    .digestInit             = SeosCrypto_digestInit,
    .digestClose            = SeosCrypto_digestClose,
    .digestUpdate           = SeosCrypto_digestUpdate,
    .digestFinalize         = SeosCrypto_digestFinalize,
    .keyInit                = SeosCrypto_keyInit,
    .keyGenerate            = SeosCrypto_keyGenerate,
    .keyGeneratePair        = SeosCrypto_keyGeneratePair,
    .keyImport              = SeosCrypto_keyImport,
    .keyExport              = SeosCrypto_keyExport,
    .keyDeInit              = SeosCrypto_keyDeInit,
    .signatureInit          = SeosCrypto_signatureInit,
    .signatureDeInit        = SeosCrypto_signatureDeInit,
    .signatureSign          = SeosCrypto_signatureSign,
    .signatureVerify        = SeosCrypto_signatureVerify,
    .agreementInit          = SeosCrypto_agreementInit,
    .agreementDeInit        = SeosCrypto_agreementDeInit,
    .agreementComputeShared = SeosCrypto_agreementComputeShared,
    .cipherInit             = SeosCrypto_cipherInit,
    .cipherClose            = SeosCrypto_cipherClose,
    .cipherUpdate           = SeosCrypto_cipherUpdate,
    .cipherUpdateAd         = SeosCrypto_cipherUpdateAd,
    .cipherFinalize         = SeosCrypto_cipherFinalize,
    .cipherVerifyTag        = SeosCrypto_cipherVerifyTag,
    .deInit                 = SeosCrypto_deInit
};

// Private static functions ----------------------------------------------------

// -1 = not found
static size_t
SeosCrypto_findHandle(PointerVector* v, Pointer handle)
{
    size_t vectorSize = PointerVector_getSize(v);

    for (size_t i = 0; i < vectorSize; i++)
    {
        if (handle == PointerVector_getElementAt(v, i))
        {
            return i;
        }
    }
    Debug_LOG_ERROR("%s: unable to find handle %p, in vector %p",
                    __func__, handle, v);
    return -1;
}

static void
SeosCrypto_removeHandle(PointerVector* v, size_t pos)
{
    PointerVector_replaceElementAt(v, pos, PointerVector_getBack(v));
    PointerVector_popBack(v);
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCrypto_init(SeosCrypto*             self,
                SeosCrypto_MallocFunc   mallocFunc,
                SeosCrypto_FreeFunc     freeFunc,
                SeosCrypto_EntropyFunc  entropyFunc,
                void*                   entropyCtx)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    memset(self, 0, sizeof(*self));

    if (NULL != mallocFunc && NULL != freeFunc)
    {
        self->mem.memIf.malloc   = mallocFunc;
        self->mem.memIf.free     = freeFunc;

        if (!PointerVector_ctor(&self->digestHandleVector, 1))
        {
            retval = SEOS_ERROR_ABORTED;
            goto exit;
        }
        else if (!PointerVector_ctor(&self->keyHandleVector, 1))
        {
            retval = SEOS_ERROR_ABORTED;
            goto err0;
        }
        else if (!PointerVector_ctor(&self->cipherHandleVector, 1))
        {
            retval = SEOS_ERROR_ABORTED;
            goto err1;
        }
        else if (!PointerVector_ctor(&self->signatureHandleVector, 1))
        {
            retval = SEOS_ERROR_ABORTED;
            goto err2;
        }
        else if (!PointerVector_ctor(&self->agreementHandleVector, 1))
        {
            retval = SEOS_ERROR_ABORTED;
            goto err3;
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (NULL != entropyFunc)
    {
        if ((retval = SeosCryptoRng_init(&self->mem.memIf, &self->cryptoRng,
                                         entropyFunc,
                                         entropyCtx)) != SEOS_SUCCESS)
        {
            goto err4;
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto err4;
    }

    self->parent.vtable = &SeosCrypto_vtable;
    retval = SEOS_SUCCESS;
    goto exit;

err4:
    PointerVector_dtor(&self->agreementHandleVector);
err3:
    PointerVector_dtor(&self->signatureHandleVector);
err2:
    PointerVector_dtor(&self->cipherHandleVector);
err1:
    PointerVector_dtor(&self->keyHandleVector);
err0:
    PointerVector_dtor(&self->digestHandleVector);
exit:
    return retval;
}

void
SeosCrypto_deInit(SeosCryptoCtx* api)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    SeosCryptoRng_deInit(&self->mem.memIf, &self->cryptoRng);

    PointerVector_dtor(&self->agreementHandleVector);
    PointerVector_dtor(&self->signatureHandleVector);
    PointerVector_dtor(&self->cipherHandleVector);
    PointerVector_dtor(&self->keyHandleVector);
    PointerVector_dtor(&self->digestHandleVector);
}

//-------------------------- Crpyto API functions ------------------------------

seos_err_t
SeosCrypto_rngGetBytes(SeosCryptoCtx*   api,
                       void**           buf,
                       size_t           bufLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    return SeosCryptoRng_getBytes(&self->cryptoRng, buf, bufLen);
}

seos_err_t
SeosCrypto_rngReSeed(SeosCryptoCtx*     api,
                     const void*        seed,
                     size_t             seedLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    return SeosCryptoRng_reSeed(&self->cryptoRng, seed, seedLen);
}

seos_err_t
SeosCrypto_digestInit(SeosCryptoCtx*                api,
                      SeosCrypto_DigestHandle*   pDigestHandle,
                      unsigned                      algorithm,
                      void*                         iv,
                      size_t                        ivLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    *pDigestHandle = self->mem.memIf.malloc(sizeof(SeosCryptoDigest));

    if (NULL == *pDigestHandle)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto exit;
    }
    else
    {
        retval = SeosCryptoDigest_init(&self->mem.memIf,
                                       *pDigestHandle,
                                       algorithm,
                                       iv,
                                       ivLen);
        if (retval != SEOS_SUCCESS)
        {
            goto err0;
        }
        else if (!PointerVector_pushBack(&self->digestHandleVector,
                                         *pDigestHandle))
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err1;
        }
        else
        {
            goto exit;
        }
    }
err1:
    SeosCryptoDigest_deInit(&self->mem.memIf, *pDigestHandle);
err0:
    self->mem.memIf.free(*pDigestHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_digestClose(SeosCryptoCtx*           api,
                       SeosCrypto_DigestHandle  digestHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_SUCCESS;
    size_t handlePos = SeosCrypto_findHandle(&self->digestHandleVector,
                                             digestHandle);
    if (handlePos != -1)
    {
        SeosCryptoDigest_deInit(&self->mem.memIf, digestHandle);
        SeosCrypto_removeHandle(&self->digestHandleVector, handlePos);
        self->mem.memIf.free(digestHandle);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_digestUpdate(SeosCryptoCtx*           api,
                        SeosCrypto_DigestHandle  digestHandle,
                        const void*              data,
                        size_t                   len)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    size_t handlePos = SeosCrypto_findHandle(&self->digestHandleVector,
                                             digestHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoDigest_update(digestHandle, data, len);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_digestFinalize(SeosCryptoCtx*          api,
                          SeosCrypto_DigestHandle digestHandle,
                          const void*             data,
                          size_t                  len,
                          void**                  digest,
                          size_t*                 digestSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    size_t handlePos = SeosCrypto_findHandle(&self->digestHandleVector,
                                             digestHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoDigest_finalize(digestHandle,
                                           data,
                                           len,
                                           digest,
                                           digestSize);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_signatureInit(SeosCryptoCtx*                api,
                         SeosCrypto_SignatureHandle*   pSigHandle,
                         unsigned int                  algorithm,
                         SeosCrypto_KeyHandle          prvHandle,
                         SeosCrypto_KeyHandle          pubHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    *pSigHandle = self->mem.memIf.malloc(sizeof(SeosCryptoSignature));
    if (NULL == *pSigHandle)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto exit;
    }
    else
    {
        retval = SeosCryptoSignature_init(&self->mem.memIf, *pSigHandle, algorithm,
                                          prvHandle, pubHandle);
        if (retval != SEOS_SUCCESS)
        {
            goto err0;
        }
        else if (!PointerVector_pushBack(&self->signatureHandleVector,
                                         *pSigHandle))
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err1;
        }
        else
        {
            goto exit;
        }
    }
err1:
    SeosCryptoSignature_deInit(&self->mem.memIf, *pSigHandle);
err0:
    self->mem.memIf.free(*pSigHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_signatureDeInit(SeosCryptoCtx*               api,
                           SeosCrypto_SignatureHandle   sigHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCrypto* self = (SeosCrypto*) api;

    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    size_t handlePos = SeosCrypto_findHandle(&self->signatureHandleVector,
                                             sigHandle);
    if (handlePos != -1)
    {
        if ((retval = SeosCryptoSignature_deInit(&self->mem.memIf,
                                                 sigHandle)) != SEOS_SUCCESS)
        {
            SeosCrypto_removeHandle(&self->signatureHandleVector, handlePos);
            self->mem.memIf.free(sigHandle);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

seos_err_t
SeosCrypto_signatureSign(SeosCryptoCtx*                 api,
                         SeosCrypto_SignatureHandle     sigHandle,
                         const void*                    hash,
                         size_t                         hashSize,
                         void**                         signature,
                         size_t*                        signatureSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->signatureHandleVector, sigHandle) != -1 ?
           SeosCryptoSignature_sign(sigHandle, &self->cryptoRng, hash, hashSize, signature,
                                    signatureSize) : SEOS_ERROR_INVALID_HANDLE;
}

seos_err_t
SeosCrypto_signatureVerify(SeosCryptoCtx*                 api,
                           SeosCrypto_SignatureHandle     sigHandle,
                           const void*                    hash,
                           size_t                         hashSize,
                           const void*                    signature,
                           size_t                         signatureSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->signatureHandleVector, sigHandle) != -1 ?
           SeosCryptoSignature_verify(sigHandle, &self->cryptoRng, hash, hashSize,
                                      signature, signatureSize) : SEOS_ERROR_INVALID_HANDLE;
}

seos_err_t
SeosCrypto_agreementInit(SeosCryptoCtx*                api,
                         SeosCrypto_AgreementHandle*   pAgrHandle,
                         unsigned int                  algorithm,
                         SeosCrypto_KeyHandle          prvHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCrypto_findHandle(&self->keyHandleVector, prvHandle) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if ((*pAgrHandle = self->mem.memIf.malloc(
                                sizeof(SeosCryptoAgreement))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoAgreement_init(&self->mem.memIf, *pAgrHandle, algorithm,
                                           prvHandle)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->agreementHandleVector, *pAgrHandle))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return retval;

err1:
    SeosCryptoAgreement_deInit(&self->mem.memIf, *pAgrHandle);
err0:
    self->mem.memIf.free(*pAgrHandle);
    return retval;
}

seos_err_t
SeosCrypto_agreementDeInit(SeosCryptoCtx*               api,
                           SeosCrypto_AgreementHandle   agrHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCrypto* self = (SeosCrypto*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if ((handlePos = SeosCrypto_findHandle(&self->agreementHandleVector,
                                           agrHandle)) != -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((retval = SeosCryptoAgreement_deInit(&self->mem.memIf,
                                             agrHandle)) != SEOS_SUCCESS)
    {
        SeosCrypto_removeHandle(&self->agreementHandleVector, handlePos);
        self->mem.memIf.free(agrHandle);
    }

    return retval;
}

seos_err_t
SeosCrypto_agreementComputeShared(SeosCryptoCtx*                 api,
                                  SeosCrypto_AgreementHandle     agrHandle,
                                  SeosCrypto_KeyHandle           pubHandle,
                                  void**                         shared,
                                  size_t*                        sharedSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->agreementHandleVector, agrHandle) != -1
           && SeosCrypto_findHandle(&self->keyHandleVector, pubHandle) != -1 ?
           SeosCryptoAgreement_computeShared(agrHandle, &self->cryptoRng, pubHandle,
                                             shared, sharedSize) : SEOS_ERROR_INVALID_HANDLE;
}

seos_err_t
SeosCrypto_keyInit(SeosCryptoCtx*                   api,
                   SeosCrypto_KeyHandle*            pKeyHandle,
                   unsigned int                     type,
                   SeosCryptoKey_Flag               flags,
                   size_t                           bits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable
        || NULL == pKeyHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    *pKeyHandle = self->mem.memIf.malloc(sizeof(SeosCryptoKey));
    if (NULL == *pKeyHandle)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto exit;
    }
    else
    {
        retval = SeosCryptoKey_init(&self->mem.memIf, *pKeyHandle, type, flags, bits);
        if (retval != SEOS_SUCCESS)
        {
            goto err0;
        }
        else if (!PointerVector_pushBack(&self->keyHandleVector, *pKeyHandle))
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err1;
        }
    }
    goto exit;

err1:
    SeosCryptoKey_deInit(&self->mem.memIf, *pKeyHandle);
err0:
    self->mem.memIf.free(*pKeyHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_keyGenerate(SeosCryptoCtx*               api,
                       SeosCrypto_KeyHandle         keyHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) != -1 ?
           SeosCryptoKey_generate(keyHandle, &self->cryptoRng) :
           SEOS_ERROR_INVALID_HANDLE;
}

seos_err_t
SeosCrypto_keyGeneratePair(SeosCryptoCtx*           api,
                           SeosCrypto_KeyHandle     prvKeyHandle,
                           SeosCrypto_KeyHandle     pubKeyHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return ((SeosCrypto_findHandle(&self->keyHandleVector, prvKeyHandle) != -1) &&
            (SeosCrypto_findHandle(&self->keyHandleVector, pubKeyHandle) != -1)) ?
           SeosCryptoKey_generatePair(prvKeyHandle, pubKeyHandle, &self->cryptoRng) :
           SEOS_ERROR_INVALID_HANDLE;
}

seos_err_t
SeosCrypto_keyImport(SeosCryptoCtx*                 api,
                     SeosCrypto_KeyHandle           keyHandle,
                     SeosCrypto_KeyHandle           wrapKeyHandle,
                     const void*                    keyBytes,
                     size_t                         keySize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == wrapKeyHandle)
    {
        return (SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) != -1) ?
               SeosCryptoKey_import(keyHandle, wrapKeyHandle, keyBytes, keySize) :
               SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        return ((SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) != -1) &&
                (SeosCrypto_findHandle(&self->keyHandleVector, wrapKeyHandle) != -1)) ?
               SeosCryptoKey_import(keyHandle, wrapKeyHandle, keyBytes, keySize) :
               SEOS_ERROR_INVALID_HANDLE;
    }
}

seos_err_t
SeosCrypto_keyExport(SeosCryptoCtx*                 api,
                     SeosCrypto_KeyHandle           keyHandle,
                     SeosCrypto_KeyHandle           wrapKeyHandle,
                     void**                         buf,
                     size_t*                        bufSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == wrapKeyHandle)
    {
        return (SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) != -1) ?
               SeosCryptoKey_export(keyHandle, wrapKeyHandle, buf, bufSize) :
               SEOS_ERROR_INVALID_HANDLE;
    }
    else
    {
        return ((SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) != -1) &&
                (SeosCrypto_findHandle(&self->keyHandleVector, wrapKeyHandle) != -1)) ?
               SeosCryptoKey_export(keyHandle, wrapKeyHandle, buf, bufSize) :
               SEOS_ERROR_INVALID_HANDLE;
    }
}

seos_err_t
SeosCrypto_keyDeInit(SeosCryptoCtx*                 api,
                     SeosCrypto_KeyHandle           keyHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCrypto* self = (SeosCrypto*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    handlePos = SeosCrypto_findHandle(&self->keyHandleVector, keyHandle);
    if (-1 != handlePos)
    {
        retval = SeosCryptoKey_deInit(&self->mem.memIf, keyHandle);
        if (SEOS_SUCCESS == retval)
        {
            SeosCrypto_removeHandle(&self->keyHandleVector, handlePos);
            self->mem.memIf.free(keyHandle);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

seos_err_t
SeosCrypto_cipherInit(SeosCryptoCtx*                api,
                      SeosCrypto_CipherHandle*      pCipherHandle,
                      unsigned int                  algorithm,
                      SeosCrypto_KeyHandle          key,
                      const void*                   iv,
                      size_t                        ivLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (SeosCrypto_findHandle(&self->keyHandleVector, key) == -1)
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
        goto exit;
    }

    *pCipherHandle = self->mem.memIf.malloc(sizeof(SeosCryptoCipher));
    if (NULL == *pCipherHandle)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto exit;
    }
    else
    {
        retval = SeosCryptoCipher_init(&self->mem.memIf,
                                       *pCipherHandle,
                                       algorithm,
                                       key,
                                       iv,
                                       ivLen);
        if (retval != SEOS_SUCCESS)
        {
            goto err0;
        }
        else if (!PointerVector_pushBack(&self->cipherHandleVector,
                                         *pCipherHandle))
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err1;
        }
        else
        {
            goto exit;
        }
    }
err1:
    SeosCryptoCipher_deInit(&self->mem.memIf, *pCipherHandle);
err0:
    self->mem.memIf.free(*pCipherHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_cipherClose(SeosCryptoCtx*           api,
                       SeosCrypto_CipherHandle  cipherHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                             cipherHandle);
    if (handlePos != -1)
    {
        SeosCryptoCipher* cipher = cipherHandle;

        SeosCryptoCipher_deInit(&self->mem.memIf, cipher);
        SeosCrypto_removeHandle(&self->cipherHandleVector, handlePos);

        self->mem.memIf.free(cipher);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_cipherUpdate(SeosCryptoCtx*          api,
                        SeosCrypto_CipherHandle cipherHandle,
                        const void*             input,
                        size_t                  inputSize,
                        void**                  output,
                        size_t*                 outputSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                             cipherHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoCipher_update(cipherHandle,
                                         input, inputSize,
                                         output, outputSize);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_cipherUpdateAd(SeosCryptoCtx*          api,
                          SeosCrypto_CipherHandle cipherHandle,
                          const void*             input,
                          size_t                  inputSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                             cipherHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoCipher_updateAd(cipherHandle,
                                           input, inputSize);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_cipherFinalize(SeosCryptoCtx*            api,
                          SeosCrypto_CipherHandle   cipherHandle,
                          void**                    output,
                          size_t*                   outputSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                             cipherHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoCipher_finalize(cipherHandle,
                                           output, outputSize);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}


seos_err_t
SeosCrypto_cipherVerifyTag(SeosCryptoCtx*            api,
                           SeosCrypto_CipherHandle   cipherHandle,
                           const void*               tag,
                           size_t                    tagSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                             cipherHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoCipher_verifyTag(cipherHandle,
                                            tag, tagSize);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

