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
    .digestFree             = SeosCrypto_digestFree,
    .digestProcess          = SeosCrypto_digestProcess,
    .digestFinalize         = SeosCrypto_digestFinalize,
    .keyInit                = SeosCrypto_keyInit,
    .keyGenerate            = SeosCrypto_keyGenerate,
    .keyGeneratePair        = SeosCrypto_keyGeneratePair,
    .keyImport              = SeosCrypto_keyImport,
    .keyExport              = SeosCrypto_keyExport,
    .keyFree                = SeosCrypto_keyFree,
    .signatureInit          = SeosCrypto_signatureInit,
    .signatureFree          = SeosCrypto_signatureFree,
    .signatureSign          = SeosCrypto_signatureSign,
    .signatureVerify        = SeosCrypto_signatureVerify,
    .agreementInit          = SeosCrypto_agreementInit,
    .agreementFree          = SeosCrypto_agreementFree,
    .agreementAgree         = SeosCrypto_agreementAgree,
    .cipherInit             = SeosCrypto_cipherInit,
    .cipherFree             = SeosCrypto_cipherFree,
    .cipherProcess          = SeosCrypto_cipherProcess,
    .cipherStart            = SeosCrypto_cipherStart,
    .cipherFinalize         = SeosCrypto_cipherFinalize,
    .free                   = SeosCrypto_free
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
        self->memIf.malloc = mallocFunc;
        self->memIf.free   = freeFunc;

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
        if ((retval = SeosCryptoRng_init(&self->cryptoRng, &self->memIf,
                                         (const SeosCrypto_EntropyFunc*) entropyFunc, entropyCtx)) != SEOS_SUCCESS)
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
SeosCrypto_free(SeosCryptoCtx* api)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    SeosCryptoRng_free(&self->cryptoRng, &self->memIf);

    PointerVector_dtor(&self->agreementHandleVector);
    PointerVector_dtor(&self->signatureHandleVector);
    PointerVector_dtor(&self->cipherHandleVector);
    PointerVector_dtor(&self->keyHandleVector);
    PointerVector_dtor(&self->digestHandleVector);
}

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCrypto_rngGetBytes(SeosCryptoCtx*               api,
                       const SeosCryptoRng_Flags    flags,
                       void*                        buf,
                       const size_t                 bufLen)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRng_getBytes(&self->cryptoRng, flags, buf, bufLen);
}

seos_err_t
SeosCrypto_rngReSeed(SeosCryptoCtx* api,
                     const void*    seed,
                     const size_t   seedLen)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRng_reSeed(&self->cryptoRng, seed, seedLen);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCrypto_digestInit(SeosCryptoCtx*                    api,
                      SeosCrypto_DigestHandle*          pDigestHandle,
                      const SeosCryptoDigest_Algorithm  algorithm)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable
        || NULL == pDigestHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((*pDigestHandle = self->memIf.malloc(
                                   sizeof(SeosCryptoDigest))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoDigest_init(*pDigestHandle, &self->memIf,
                                        algorithm)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->digestHandleVector, *pDigestHandle))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    SeosCryptoDigest_free(*pDigestHandle, &self->memIf);
err0:
    self->memIf.free(*pDigestHandle);

    return retval;
}

seos_err_t
SeosCrypto_digestFree(SeosCryptoCtx*                api,
                      const SeosCrypto_DigestHandle digestHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCrypto_findHandle(&self->digestHandleVector,
                                           digestHandle)) != -1)
    {
        if ((retval = SeosCryptoDigest_free(digestHandle,
                                            &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCrypto_removeHandle(&self->digestHandleVector, handlePos);
            self->memIf.free(digestHandle);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

seos_err_t
SeosCrypto_digestProcess(SeosCryptoCtx*                  api,
                         const SeosCrypto_DigestHandle   digestHandle,
                         const void*                     data,
                         const size_t                    len)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->digestHandleVector, digestHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_process(digestHandle, data, len);
}

seos_err_t
SeosCrypto_digestFinalize(SeosCryptoCtx*                api,
                          const SeosCrypto_DigestHandle digestHandle,
                          void*                         digest,
                          size_t*                       digestSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->digestHandleVector, digestHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_finalize(digestHandle, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCrypto_signatureInit(SeosCryptoCtx*                         api,
                         SeosCrypto_SignatureHandle*            pSigHandle,
                         const SeosCryptoSignature_Algorithm    algorithm,
                         const SeosCrypto_KeyHandle             prvHandle,
                         const SeosCrypto_KeyHandle             pubHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable
        || NULL == pSigHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((*pSigHandle = self->memIf.malloc(
                                sizeof(SeosCryptoSignature))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoSignature_init(*pSigHandle, &self->memIf, algorithm,
                                           prvHandle, pubHandle)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->signatureHandleVector, *pSigHandle))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    SeosCryptoSignature_free(*pSigHandle, &self->memIf);
err0:
    self->memIf.free(*pSigHandle);

    return retval;
}

seos_err_t
SeosCrypto_signatureFree(SeosCryptoCtx*                     api,
                         const SeosCrypto_SignatureHandle   sigHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCrypto* self = (SeosCrypto*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCrypto_findHandle(&self->signatureHandleVector,
                                           sigHandle)) != -1)
    {
        if ((retval = SeosCryptoSignature_free(sigHandle,
                                               &self->memIf)) != SEOS_SUCCESS)
        {
            SeosCrypto_removeHandle(&self->signatureHandleVector, handlePos);
            self->memIf.free(sigHandle);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

seos_err_t
SeosCrypto_signatureSign(SeosCryptoCtx*                     api,
                         const SeosCrypto_SignatureHandle   sigHandle,
                         const void*                        hash,
                         const size_t                       hashSize,
                         void*                              signature,
                         size_t*                            signatureSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable || NULL == hash)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > INPUT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    // Make local copy of input buffer, to allow overlapping hash/signature buffers
    memcpy(get_input_buf_ptr(self), hash, hashSize);
    return SeosCrypto_findHandle(&self->signatureHandleVector, sigHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoSignature_sign(sigHandle, &self->cryptoRng, get_input_buf_ptr(self),
                                    hashSize, signature, signatureSize);
}

seos_err_t
SeosCrypto_signatureVerify(SeosCryptoCtx*                   api,
                           const SeosCrypto_SignatureHandle sigHandle,
                           const void*                      hash,
                           const size_t                     hashSize,
                           const void*                      signature,
                           const size_t                     signatureSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->signatureHandleVector, sigHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoSignature_verify(sigHandle, &self->cryptoRng, hash, hashSize,
                                      signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCrypto_agreementInit(SeosCryptoCtx*                         api,
                         SeosCrypto_AgreementHandle*            pAgrHandle,
                         const SeosCryptoAgreement_Algorithm    algorithm,
                         const SeosCrypto_KeyHandle             prvHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable
        || NULL == pAgrHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCrypto_findHandle(&self->keyHandleVector, prvHandle) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if ((*pAgrHandle = self->memIf.malloc(
                                sizeof(SeosCryptoAgreement))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoAgreement_init(*pAgrHandle, &self->memIf, algorithm,
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
    SeosCryptoAgreement_free(*pAgrHandle, &self->memIf);
err0:
    self->memIf.free(*pAgrHandle);
    return retval;
}

seos_err_t
SeosCrypto_agreementFree(SeosCryptoCtx*                     api,
                         const SeosCrypto_AgreementHandle   agrHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCrypto* self = (SeosCrypto*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if ((handlePos = SeosCrypto_findHandle(&self->agreementHandleVector,
                                           agrHandle)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((retval = SeosCryptoAgreement_free(agrHandle,
                                           &self->memIf)) != SEOS_SUCCESS)
    {
        SeosCrypto_removeHandle(&self->agreementHandleVector, handlePos);
        self->memIf.free(agrHandle);
    }

    return retval;
}

seos_err_t
SeosCrypto_agreementAgree(SeosCryptoCtx*                    api,
                          const SeosCrypto_AgreementHandle  agrHandle,
                          const SeosCrypto_KeyHandle        pubHandle,
                          void*                             shared,
                          size_t*                           sharedSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCrypto_findHandle(&self->agreementHandleVector, agrHandle) == -1)
           || (SeosCrypto_findHandle(&self->keyHandleVector, pubHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoAgreement_agree(agrHandle, &self->cryptoRng, pubHandle,
                                     shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------

seos_err_t
SeosCrypto_keyInit(SeosCryptoCtx*               api,
                   SeosCrypto_KeyHandle*        pKeyHandle,
                   const SeosCryptoKey_Type     type,
                   const SeosCryptoKey_Flags    flags,
                   const size_t                 bits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable
        || NULL == pKeyHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    *pKeyHandle = self->memIf.malloc(sizeof(SeosCryptoKey));
    if (NULL == *pKeyHandle)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto exit;
    }
    else
    {
        retval = SeosCryptoKey_init(*pKeyHandle, &self->memIf, type, flags, bits);
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
    SeosCryptoKey_free(*pKeyHandle, &self->memIf);
err0:
    self->memIf.free(*pKeyHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_keyGenerate(SeosCryptoCtx*               api,
                       const SeosCrypto_KeyHandle   keyHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoKey_generate(keyHandle, &self->cryptoRng);
}

seos_err_t
SeosCrypto_keyGeneratePair(SeosCryptoCtx*               api,
                           const SeosCrypto_KeyHandle   prvKeyHandle,
                           const SeosCrypto_KeyHandle   pubKeyHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return ((SeosCrypto_findHandle(&self->keyHandleVector, prvKeyHandle) == -1)
            || (SeosCrypto_findHandle(&self->keyHandleVector, pubKeyHandle) == -1)) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoKey_generatePair(prvKeyHandle, pubKeyHandle, &self->cryptoRng);
}

seos_err_t
SeosCrypto_keyImport(SeosCryptoCtx*             api,
                     const SeosCrypto_KeyHandle keyHandle,
                     const SeosCrypto_KeyHandle wrapKeyHandle,
                     const void*                keyBytes,
                     const size_t               keySize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == wrapKeyHandle)
    {
        return (SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) == -1) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_import(keyHandle, wrapKeyHandle, keyBytes, keySize);
    }
    else
    {
        return ((SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) == -1)
                || (SeosCrypto_findHandle(&self->keyHandleVector, wrapKeyHandle) == -1)) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_import(keyHandle, wrapKeyHandle, keyBytes, keySize);
    }
}

seos_err_t
SeosCrypto_keyExport(SeosCryptoCtx*             api,
                     const SeosCrypto_KeyHandle keyHandle,
                     const SeosCrypto_KeyHandle wrapKeyHandle,
                     void*                      buf,
                     size_t*                    bufSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == wrapKeyHandle)
    {
        return (SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) == -1) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_export(keyHandle, wrapKeyHandle, buf, bufSize);
    }
    else
    {
        return ((SeosCrypto_findHandle(&self->keyHandleVector, keyHandle) == -1)
                || (SeosCrypto_findHandle(&self->keyHandleVector, wrapKeyHandle) == -1)) ?
               SEOS_ERROR_INVALID_HANDLE :
               SeosCryptoKey_export(keyHandle, wrapKeyHandle, buf, bufSize);
    }
}

seos_err_t
SeosCrypto_keyFree(SeosCryptoCtx*               api,
                   const SeosCrypto_KeyHandle   keyHandle)
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
        retval = SeosCryptoKey_free(keyHandle, &self->memIf);
        if (SEOS_SUCCESS == retval)
        {
            SeosCrypto_removeHandle(&self->keyHandleVector, handlePos);
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
SeosCrypto_cipherInit(SeosCryptoCtx*                    api,
                      SeosCrypto_CipherHandle*          pCipherHandle,
                      const SeosCryptoCipher_Algorithm  algorithm,
                      const SeosCrypto_KeyHandle        key,
                      const void*                       iv,
                      const size_t                      ivLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable
        || NULL == pCipherHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCrypto_findHandle(&self->keyHandleVector, key) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*pCipherHandle = self->memIf.malloc(sizeof(SeosCryptoCipher))) ==
        NULL)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    else
    {
        if ((retval = SeosCryptoCipher_init(*pCipherHandle, &self->memIf, algorithm,
                                            key,  iv, ivLen)) != SEOS_SUCCESS)
        {
            goto err0;
        }
        else if (!PointerVector_pushBack(&self->cipherHandleVector, *pCipherHandle))
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err1;
        }
    }

    return retval;

err1:
    SeosCryptoCipher_free(*pCipherHandle, &self->memIf);
err0:
    self->memIf.free(*pCipherHandle);

    return retval;
}

seos_err_t
SeosCrypto_cipherFree(SeosCryptoCtx*                api,
                      const SeosCrypto_CipherHandle cipherHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                           cipherHandle)) != -1)
    {
        if ((retval = SeosCryptoCipher_free(cipherHandle,
                                            &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCrypto_removeHandle(&self->cipherHandleVector, handlePos);
            self->memIf.free(cipherHandle);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

seos_err_t
SeosCrypto_cipherProcess(SeosCryptoCtx*                  api,
                         const SeosCrypto_CipherHandle   cipherHandle,
                         const void*                     input,
                         const size_t                    inputSize,
                         void*                           output,
                         size_t*                         outputSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable || NULL == input)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > INPUT_BUFFER_SIZE)
    {
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    // Make local copy of input buffer, to allow overlapping input/output buffers
    memcpy(get_input_buf_ptr(self), input, inputSize);
    return (SeosCrypto_findHandle(&self->cipherHandleVector, cipherHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_process(cipherHandle, get_input_buf_ptr(self), inputSize,
                                    output, outputSize);
}

seos_err_t
SeosCrypto_cipherStart(SeosCryptoCtx*                   api,
                       const SeosCrypto_CipherHandle    cipherHandle,
                       const void*                      input,
                       const size_t                     inputSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCrypto_findHandle(&self->cipherHandleVector, cipherHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_start(cipherHandle, input, inputSize);
}

seos_err_t
SeosCrypto_cipherFinalize(SeosCryptoCtx*                    api,
                          const SeosCrypto_CipherHandle     cipherHandle,
                          void*                             buf,
                          size_t*                           bufSize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    if (NULL == api || self->parent.vtable != &SeosCrypto_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCrypto_findHandle(&self->cipherHandleVector, cipherHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_finalize(cipherHandle, buf, bufSize);
}