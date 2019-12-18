/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoCipher.h"
#include "lib/SeosCryptoKey.h"
#include "lib/SeosCryptoRng.h"
#include "lib/SeosCryptoDigest.h"
#include "lib/SeosCryptoMac.h"
#include "lib/SeosCryptoSignature.h"
#include "lib/SeosCryptoAgreement.h"

#include "SeosCryptoLib.h"

#include "LibDebug/Debug.h"

#include <string.h>

static const SeosCryptoApi_Vtable SeosCryptoLib_vtable =
{
    .rngGetBytes        = SeosCryptoLib_rngGetBytes,
    .rngReSeed          = SeosCryptoLib_rngReSeed,
    .macInit            = SeosCryptoLib_macInit,
    .macFree            = SeosCryptoLib_macFree,
    .macStart           = SeosCryptoLib_macStart,
    .macProcess         = SeosCryptoLib_macProcess,
    .macFinalize        = SeosCryptoLib_macFinalize,
    .digestInit         = SeosCryptoLib_digestInit,
    .digestFree         = SeosCryptoLib_digestFree,
    .digestClone        = SeosCryptoLib_digestClone,
    .digestProcess      = SeosCryptoLib_digestProcess,
    .digestFinalize     = SeosCryptoLib_digestFinalize,
    .keyGenerate        = SeosCryptoLib_keyGenerate,
    .keyMakePublic      = SeosCryptoLib_keyMakePublic,
    .keyImport          = SeosCryptoLib_keyImport,
    .keyExport          = SeosCryptoLib_keyExport,
    .keyGetParams       = SeosCryptoLib_keyGetParams,
    .keyLoadParams      = SeosCryptoLib_keyLoadParams,
    .keyFree            = SeosCryptoLib_keyFree,
    .signatureInit      = SeosCryptoLib_signatureInit,
    .signatureFree      = SeosCryptoLib_signatureFree,
    .signatureSign      = SeosCryptoLib_signatureSign,
    .signatureVerify    = SeosCryptoLib_signatureVerify,
    .agreementInit      = SeosCryptoLib_agreementInit,
    .agreementFree      = SeosCryptoLib_agreementFree,
    .agreementAgree     = SeosCryptoLib_agreementAgree,
    .cipherInit         = SeosCryptoLib_cipherInit,
    .cipherFree         = SeosCryptoLib_cipherFree,
    .cipherProcess      = SeosCryptoLib_cipherProcess,
    .cipherStart        = SeosCryptoLib_cipherStart,
    .cipherFinalize     = SeosCryptoLib_cipherFinalize,
    .free               = SeosCryptoLib_free
};

// Private static functions ----------------------------------------------------

// -1 = not found
static size_t
SeosCryptoLib_findHandle(PointerVector* v, Pointer handle)
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
SeosCryptoLib_removeHandle(PointerVector* v, size_t pos)
{
    PointerVector_replaceElementAt(v, pos, PointerVector_getBack(v));
    PointerVector_popBack(v);
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoLib_init(SeosCryptoLib*                 self,
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
SeosCryptoLib_free(SeosCryptoApi_Context* api)
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

// -------------------------------- RNG API ------------------------------------

seos_err_t
SeosCryptoLib_rngGetBytes(SeosCryptoApi_Context*       api,
                          const SeosCryptoApi_Rng_Flag flags,
                          void*                        buf,
                          const size_t                 bufLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRng_getBytes(&self->cryptoRng, flags, buf, bufLen);
}

seos_err_t
SeosCryptoLib_rngReSeed(SeosCryptoApi_Context* api,
                        const void*            seed,
                        const size_t           seedLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRng_reSeed(&self->cryptoRng, seed, seedLen);
}

// -------------------------------- MAC API ------------------------------------

seos_err_t
SeosCryptoLib_macInit(SeosCryptoApi_Context*      api,
                      SeosCryptoApi_Mac*          pMacHandle,
                      const SeosCryptoApi_Mac_Alg algorithm)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
        || NULL == pMacHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((*pMacHandle = self->memIf.malloc(sizeof(SeosCryptoMac))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((retval = SeosCryptoMac_init(*pMacHandle, &self->memIf,
                                     algorithm)) != SEOS_SUCCESS)
    {
        goto err0;
    }
    else if (!PointerVector_pushBack(&self->macHandleVector, *pMacHandle))
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto err1;
    }

    return SEOS_SUCCESS;

err1:
    SeosCryptoMac_free(*pMacHandle, &self->memIf);
err0:
    self->memIf.free(*pMacHandle);

    return retval;
}

seos_err_t
SeosCryptoLib_macFree(SeosCryptoApi_Context*  api,
                      const SeosCryptoApi_Mac macHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->macHandleVector,
                                              macHandle)) != -1)
    {
        if ((retval = SeosCryptoMac_free(macHandle, &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->macHandleVector, handlePos);
            self->memIf.free(macHandle);
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }

    return retval;
}

seos_err_t
SeosCryptoLib_macStart(SeosCryptoApi_Context*  api,
                       const SeosCryptoApi_Mac macHandle,
                       const void*             secret,
                       const size_t            secretSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->macHandleVector, macHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoMac_start(macHandle, secret, secretSize);
}

seos_err_t
SeosCryptoLib_macProcess(SeosCryptoApi_Context*  api,
                         const SeosCryptoApi_Mac macHandle,
                         const void*             data,
                         const size_t            dataLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->macHandleVector, macHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoMac_process(macHandle, data, dataLen);
}

seos_err_t
SeosCryptoLib_macFinalize(SeosCryptoApi_Context*  api,
                          const SeosCryptoApi_Mac macHandle,
                          void*                   mac,
                          size_t*                 macSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->macHandleVector, macHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoMac_finalize(macHandle, mac, macSize);
}

// ------------------------------ Digest API -----------------------------------

seos_err_t
SeosCryptoLib_digestInit(SeosCryptoApi_Context*         api,
                         SeosCryptoApi_Digest*          pDigestHandle,
                         const SeosCryptoApi_Digest_Alg algorithm)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
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
SeosCryptoLib_digestFree(SeosCryptoApi_Context*     api,
                         const SeosCryptoApi_Digest digestHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->digestHandleVector,
                                              digestHandle)) != -1)
    {
        if ((retval = SeosCryptoDigest_free(digestHandle,
                                            &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->digestHandleVector, handlePos);
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
SeosCryptoLib_digestClone(SeosCryptoApi_Context*     api,
                          const SeosCryptoApi_Digest dstDigHandle,
                          const SeosCryptoApi_Digest srcDigHandle)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->digestHandleVector, dstDigHandle) == -1
           ||
           SeosCryptoLib_findHandle(&self->digestHandleVector, srcDigHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_clone(dstDigHandle, srcDigHandle);
}

seos_err_t
SeosCryptoLib_digestProcess(SeosCryptoApi_Context*     api,
                            const SeosCryptoApi_Digest digestHandle,
                            const void*                data,
                            const size_t               dataLen)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->digestHandleVector, digestHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_process(digestHandle, data, dataLen);
}

seos_err_t
SeosCryptoLib_digestFinalize(SeosCryptoApi_Context*     api,
                             const SeosCryptoApi_Digest digestHandle,
                             void*                      digest,
                             size_t*                    digestSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->digestHandleVector, digestHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoDigest_finalize(digestHandle, digest, digestSize);
}

// ----------------------------- Signature API ---------------------------------

seos_err_t
SeosCryptoLib_signatureInit(SeosCryptoApi_Context*            api,
                            SeosCryptoApi_Signature*          pSigHandle,
                            const SeosCryptoApi_Signature_Alg algorithm,
                            const SeosCryptoApi_Digest_Alg    digest,
                            const SeosCryptoApi_Key           prvHandle,
                            const SeosCryptoApi_Key           pubHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
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
                                           digest, prvHandle, pubHandle)) != SEOS_SUCCESS)
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
SeosCryptoLib_signatureFree(SeosCryptoApi_Context*        api,
                            const SeosCryptoApi_Signature sigHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->signatureHandleVector,
                                              sigHandle)) != -1)
    {
        if ((retval = SeosCryptoSignature_free(sigHandle,
                                               &self->memIf)) != SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->signatureHandleVector, handlePos);
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
SeosCryptoLib_signatureSign(SeosCryptoApi_Context*        api,
                            const SeosCryptoApi_Signature sigHandle,
                            const void*                   hash,
                            const size_t                  hashSize,
                            void*                         signature,
                            size_t*                       signatureSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable || NULL == hash)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping hash/signature buffers
    memcpy(self->buffer, hash, hashSize);
    return SeosCryptoLib_findHandle(&self->signatureHandleVector, sigHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoSignature_sign(sigHandle, &self->cryptoRng, self->buffer,
                                    hashSize, signature, signatureSize);
}

seos_err_t
SeosCryptoLib_signatureVerify(SeosCryptoApi_Context*        api,
                              const SeosCryptoApi_Signature sigHandle,
                              const void*                   hash,
                              const size_t                  hashSize,
                              const void*                   signature,
                              const size_t                  signatureSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoLib_findHandle(&self->signatureHandleVector, sigHandle) == -1 ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoSignature_verify(sigHandle, &self->cryptoRng, hash, hashSize,
                                      signature, signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

seos_err_t
SeosCryptoLib_agreementInit(SeosCryptoApi_Context*            api,
                            SeosCryptoApi_Agreement*          pAgrHandle,
                            const SeosCryptoApi_Agreement_Alg algorithm,
                            const SeosCryptoApi_Key           prvHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
        || NULL == pAgrHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, prvHandle) == -1)
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
SeosCryptoLib_agreementFree(SeosCryptoApi_Context*        api,
                            const SeosCryptoApi_Agreement agrHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if ((handlePos = SeosCryptoLib_findHandle(&self->agreementHandleVector,
                                              agrHandle)) == -1)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((retval = SeosCryptoAgreement_free(agrHandle,
                                           &self->memIf)) != SEOS_SUCCESS)
    {
        SeosCryptoLib_removeHandle(&self->agreementHandleVector, handlePos);
        self->memIf.free(agrHandle);
    }

    return retval;
}

seos_err_t
SeosCryptoLib_agreementAgree(SeosCryptoApi_Context*        api,
                             const SeosCryptoApi_Agreement agrHandle,
                             const SeosCryptoApi_Key       pubHandle,
                             void*                         shared,
                             size_t*                       sharedSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->agreementHandleVector, agrHandle) == -1)
           || (SeosCryptoLib_findHandle(&self->keyHandleVector, pubHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoAgreement_agree(agrHandle, &self->cryptoRng, pubHandle,
                                     shared, sharedSize);
}

// -------------------------------- Key API ------------------------------------
seos_err_t
SeosCryptoLib_keyGenerate(SeosCryptoApi_Context*        api,
                          SeosCryptoApi_Key*            pKeyHandle,
                          const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
        || NULL == pKeyHandle)
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
SeosCryptoLib_keyMakePublic(SeosCryptoApi_Context*           api,
                            SeosCryptoApi_Key*               pPubKeyHandle,
                            const SeosCryptoApi_Key          prvKeyHandle,
                            const SeosCryptoApi_Key_Attribs* attribs)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
        || NULL == pPubKeyHandle)
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
SeosCryptoLib_keyImport(SeosCryptoApi_Context*        api,
                        SeosCryptoApi_Key*            pKeyHandle,
                        const SeosCryptoApi_Key       wrapKeyHandle,
                        const SeosCryptoApi_Key_Data* keyData)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
        || NULL == pKeyHandle)
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
SeosCryptoLib_keyExport(SeosCryptoApi_Context*  api,
                        const SeosCryptoApi_Key keyHandle,
                        const SeosCryptoApi_Key wrapKeyHandle,
                        SeosCryptoApi_Key_Data* keyData)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
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
SeosCryptoLib_keyGetParams(SeosCryptoApi_Context*  api,
                           const SeosCryptoApi_Key keyHandle,
                           void*                   keyParams,
                           size_t*                 paramSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->keyHandleVector, keyHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoKey_getParams(keyHandle, keyParams, paramSize);
}

seos_err_t
SeosCryptoLib_keyLoadParams(SeosCryptoApi_Context*        api,
                            const SeosCryptoApi_Key_Param name,
                            void*                         keyParams,
                            size_t*                       paramSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoKey_loadParams(name, keyParams, paramSize);
}

seos_err_t
SeosCryptoLib_keyFree(SeosCryptoApi_Context*  api,
                      const SeosCryptoApi_Key keyHandle)
{
    seos_err_t retval = SEOS_SUCCESS;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
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
SeosCryptoLib_cipherInit(SeosCryptoApi_Context*         api,
                         SeosCryptoApi_Cipher*          pCipherHandle,
                         const SeosCryptoApi_Cipher_Alg algorithm,
                         const SeosCryptoApi_Key        key,
                         const void*                    iv,
                         const size_t                   ivLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
        || NULL == pCipherHandle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (SeosCryptoLib_findHandle(&self->keyHandleVector, key) == -1)
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
SeosCryptoLib_cipherFree(SeosCryptoApi_Context*     api,
                         const SeosCryptoApi_Cipher cipherHandle)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCryptoLib* self = (SeosCryptoLib*) api;
    size_t handlePos;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((handlePos = SeosCryptoLib_findHandle(&self->cipherHandleVector,
                                              cipherHandle)) != -1)
    {
        if ((retval = SeosCryptoCipher_free(cipherHandle,
                                            &self->memIf)) == SEOS_SUCCESS)
        {
            SeosCryptoLib_removeHandle(&self->cipherHandleVector, handlePos);
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
SeosCryptoLib_cipherProcess(SeosCryptoApi_Context*     api,
                            const SeosCryptoApi_Cipher cipherHandle,
                            const void*                input,
                            const size_t               inputSize,
                            void*                      output,
                            size_t*                    outputSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable
        || NULL == input)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > SeosCryptoLib_SIZE_BUFFER)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of input buffer, to allow overlapping input/output buffers
    memcpy(self->buffer, input, inputSize);
    return (SeosCryptoLib_findHandle(&self->cipherHandleVector,
                                     cipherHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_process(cipherHandle, self->buffer, inputSize,
                                    output, outputSize);
}

seos_err_t
SeosCryptoLib_cipherStart(SeosCryptoApi_Context*     api,
                          const SeosCryptoApi_Cipher cipherHandle,
                          const void*                input,
                          const size_t               inputSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->cipherHandleVector,
                                     cipherHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_start(cipherHandle, input, inputSize);
}

seos_err_t
SeosCryptoLib_cipherFinalize(SeosCryptoApi_Context*     api,
                             const SeosCryptoApi_Cipher cipherHandle,
                             void*                      buf,
                             size_t*                    bufSize)
{
    SeosCryptoLib* self = (SeosCryptoLib*) api;

    if (NULL == api || self->parent.vtable != &SeosCryptoLib_vtable)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return (SeosCryptoLib_findHandle(&self->cipherHandleVector,
                                     cipherHandle) == -1) ?
           SEOS_ERROR_INVALID_HANDLE :
           SeosCryptoCipher_finalize(cipherHandle, buf, bufSize);
}