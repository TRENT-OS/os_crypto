/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoCipher.h"
#include "SeosCryptoKey.h"
#include "SeosCryptoRng.h"
#include "SeosCryptoDigest.h"
#include "SeosCrypto.h"

#include "LibDebug/Debug.h"

static const SeosCryptoCtx_Vtable SeosCrypto_vtable =
{
    .rngGetBytes     = SeosCrypto_rngGetBytes,
    .rngReSeed       = SeosCrypto_rngReSeed,
    .digestInit      = SeosCrypto_digestInit,
    .digestClose     = SeosCrypto_digestClose,
    .digestUpdate    = SeosCrypto_digestUpdate,
    .digestFinalize  = SeosCrypto_digestFinalize,
    .keyInit         = SeosCrypto_keyInit,
    .keyGenerate     = SeosCrypto_keyGenerate,
    .keyGeneratePair = SeosCrypto_keyGeneratePair,
    .keyImport       = SeosCrypto_keyImport,
    .keyExport       = SeosCrypto_keyExport,
    .keyDeInit       = SeosCrypto_keyDeInit,
    .cipherInit      = SeosCrypto_cipherInit,
    .cipherClose     = SeosCrypto_cipherClose,
    .cipherUpdate    = SeosCrypto_cipherUpdate,
    .cipherUpdateAd  = SeosCrypto_cipherUpdateAd,
    .cipherFinalize  = SeosCrypto_cipherFinalize,
    .cipherVerifyTag = SeosCrypto_cipherVerifyTag,
    .deInit          = SeosCrypto_deInit
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
            goto err2;
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto err2;
    }

    self->parent.vtable = &SeosCrypto_vtable;
    retval = SEOS_SUCCESS;
    goto exit;

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

    PointerVector_dtor(&self->digestHandleVector);
    PointerVector_dtor(&self->keyHandleVector);
    PointerVector_dtor(&self->cipherHandleVector);

    SeosCryptoRng_deInit(&self->mem.memIf, &self->cryptoRng);
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
SeosCrypto_keyInit(SeosCryptoCtx*                   api,
                   SeosCrypto_KeyHandle*            pKeyHandle,
                   unsigned int                     type,
                   SeosCryptoKey_Flag               flags,
                   size_t                           bits)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    SeosCrypto* self = (SeosCrypto*) api;

    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

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
    Debug_PRINTF("\n%s\n", __func__);
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCrypto_keyGeneratePair(SeosCryptoCtx*           api,
                           SeosCrypto_KeyHandle     prvKeyHandle,
                           SeosCrypto_KeyHandle     pubKeyHandle)
{
    Debug_PRINTF("\n%s\n", __func__);
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCrypto_keyImport(SeosCryptoCtx*                 api,
                     SeosCrypto_KeyHandle           keyHandle,
                     SeosCrypto_KeyHandle           wrapKeyHandle,
                     const void*                    keyBytes,
                     size_t                         keySize)
{
    SeosCrypto* self = (SeosCrypto*) api;

    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

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

    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

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

    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosCrypto_vtable);

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

