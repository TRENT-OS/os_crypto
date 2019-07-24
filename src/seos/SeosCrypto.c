/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCrypto.h"

#include "LibDebug/Debug.h"
#include "seos_rng.h"

#include "SeosCryptoCipher.h"
#include "SeosCryptoDigest.h"
#include "limits.h"

static const SeosCryptoApi_Vtable SeosCrypto_vtable =
{
    .getRandomData  = SeosCrypto_getRandomData,
    .digestInit     = SeosCrypto_digestInit,
    .digestClose    = SeosCrypto_digestClose,
    .digestUpdate   = SeosCrypto_digestUpdate,
    .digestFinalize = SeosCrypto_digestFinalize,
    .keyGenerate    = SeosCrypto_keyGenerate,
    .keyImport      = SeosCrypto_keyImport,
    .keyClose       = SeosCrypto_keyClose,
    .cipherInit     = SeosCrypto_cipherInit,
    .cipherClose    = SeosCrypto_cipherClose,
    .cipherUpdate   = SeosCrypto_cipherUpdate,
    .deInit         = SeosCrypto_deInit
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
SeosCrypto_init(SeosCrypto* self,
                SeosCrypto_MallocFunc malloc,
                SeosCrypto_FreeFunc free,
                void* bufferCtx,
                size_t* lenBufferCtx)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    memset(self, 0, sizeof(*self));

    if (malloc != NULL && free != NULL)
    {
        self->mem.memIf.malloc   = malloc;
        self->mem.memIf.free     = free;

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
        else
        {
            self->parent.vtable = &SeosCrypto_vtable;
            retval = SEOS_SUCCESS;
            goto exit;
        }
    }
    else
    {
        // this implementation will be done later
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
err1:
    PointerVector_dtor(&self->keyHandleVector);
err0:
    PointerVector_dtor(&self->digestHandleVector);
exit:
    return retval;
}

void
SeosCrypto_deInit(SeosCryptoApi* api)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    PointerVector_dtor(&self->cipherHandleVector);
    PointerVector_dtor(&self->keyHandleVector);
    PointerVector_dtor(&self->digestHandleVector);

    if (self->isRngInitialized)
    {
        seos_rng_free(&self->rng);
    }
}


//-------------------------- Crpyto API functions ------------------------------

seos_err_t
SeosCrypto_getRandomData(SeosCryptoApi* api,
                         unsigned int   flags,
                         void const*    saltBuffer,
                         size_t         saltLen,
                         void*          buffer,
                         size_t         bufferLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;

    void const* seed   = (saltBuffer != NULL)
                         ? saltBuffer : SeosCrypto_RANDOM_SEED_STR;
    size_t seedLen      = (saltBuffer != NULL)
                          ? saltLen : sizeof(SeosCrypto_RANDOM_SEED_STR) - 1;

    if (self->isRngInitialized && (saltBuffer != NULL))
    {
        seos_rng_free(&self->rng);
        self->isRngInitialized = false;
    }

    if (!self->isRngInitialized
        && seos_rng_init(&self->rng, seed, seedLen))
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else
    {
        self->isRngInitialized = true;
    }

    if (self->isRngInitialized
        && seos_rng_get_prng_bytes(&self->rng, buffer, bufferLen))
    {
        Debug_LOG_DEBUG("%s: aborted", __func__);
        retval = SEOS_ERROR_ABORTED;
    }
    return retval;
}

seos_err_t
SeosCrypto_digestInit(SeosCryptoApi*                api,
                      SeosCryptoApi_DigestHandle*   pDigestHandle,
                      unsigned                      algorithm,
                      void*                         iv,
                      size_t                        ivLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    *pDigestHandle = self->mem.memIf.malloc(sizeof(SeosCryptoDigest));

    if (NULL == *pDigestHandle)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto exit;
    }
    else
    {
        retval = SeosCryptoDigest_init(*pDigestHandle,
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
    SeosCryptoDigest_deInit(*pDigestHandle);
err0:
    self->mem.memIf.free(*pDigestHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_digestClose(SeosCryptoApi*           api,
                       SeosCryptoApi_DigestHandle  digestHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;
    size_t handlePos = SeosCrypto_findHandle(&self->digestHandleVector,
                                             digestHandle);
    if (handlePos != -1)
    {
        SeosCryptoDigest_deInit(digestHandle);
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
SeosCrypto_digestUpdate(SeosCryptoApi*           api,
                        SeosCryptoApi_DigestHandle  digestHandle,
                        const void*              data,
                        size_t                   len)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);
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
SeosCrypto_digestFinalize(SeosCryptoApi*          api,
                          SeosCryptoApi_DigestHandle digestHandle,
                          const void*             data,
                          size_t                  len,
                          void**                  digest,
                          size_t*                 digestSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

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
SeosCrypto_keyGenerate(SeosCryptoApi*           api,
                       SeosCryptoApi_KeyHandle* pKeyHandle,
                       unsigned int             algorithm,
                       unsigned int             flags,
                       size_t                   lenBits)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == pKeyHandle || !lenBits)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    else
    {
        size_t sizeRawKey   = lenBits / CHAR_BIT
                              + ((lenBits % CHAR_BIT) ? 1 : 0);
        size_t sizeObjBytes = sizeof(SeosCryptoKey) + sizeRawKey;

        *pKeyHandle = self->mem.memIf.malloc(sizeObjBytes);

        if (NULL == *pKeyHandle)
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto exit;
        }
        else
        {
            char* keyBytes
                = & (((char*) *pKeyHandle)[sizeof(SeosCryptoKey)]);

            retval = SeosCrypto_getRandomData(api,
                                              0,
                                              NULL, 0,
                                              keyBytes,
                                              sizeRawKey);
            if (retval != SEOS_SUCCESS)
            {
                goto err0;
            }
            retval = SeosCryptoKey_init(*pKeyHandle,
                                        NULL,
                                        algorithm,
                                        flags,
                                        keyBytes,
                                        lenBits);
            if (retval != SEOS_SUCCESS)
            {
                goto err0;
            }
            else if (!PointerVector_pushBack(&self->keyHandleVector,
                                             *pKeyHandle))
            {
                retval = SEOS_ERROR_INSUFFICIENT_SPACE;
                goto err1;
            }
            else
            {
                goto exit;
            }
        }
    }
err1:
    SeosCryptoKey_deInit(*pKeyHandle);
err0:
    self->mem.memIf.free(*pKeyHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_keyImport(SeosCryptoApi*         api,
                     SeosCryptoApi_KeyHandle*  pKeyHandle,
                     unsigned int           algorithm,
                     unsigned int           flags,
                     void const*            keyImportBuffer,
                     size_t                 keyImportLenBits)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == keyImportBuffer)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_keyGenerate(api,
                                        pKeyHandle,
                                        algorithm,
                                        flags,
                                        keyImportLenBits);
        if (retval == SEOS_SUCCESS)
        {
            SeosCryptoKey* pKey = *pKeyHandle;
            memcpy(pKey->bytes, keyImportBuffer, SeosCryptoKey_getSize(pKey));
        }
    }
    return retval;
}

seos_err_t
SeosCrypto_keyExport(SeosCryptoApi*         api,
                     SeosCryptoApi_KeyHandle   keyHandle,
                     void*                  buffer,
                     size_t                 bufferLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->keyHandleVector,
                                             keyHandle);
    if (handlePos != -1)
    {
        SeosCryptoKey* pKey = keyHandle;

        if (SeosCryptoKey_getSize(keyHandle) > bufferLen)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            switch (pKey->algorithm)
            {
//              export only exportable things
//            case ...:
//                memcpy(buffer, pKey->bytes, sizeRawKey);
//                break;

            default:
                retval = SEOS_ERROR_ABORTED;
            }
        }
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_keyClose(SeosCryptoApi*          api,
                    SeosCryptoApi_KeyHandle    keyHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->keyHandleVector,
                                             keyHandle);
    if (handlePos != -1)
    {
        SeosCryptoKey_deInit(keyHandle);
        SeosCrypto_removeHandle(&self->keyHandleVector, handlePos);
        self->mem.memIf.free(keyHandle);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_cipherInit(SeosCryptoApi*                api,
                      SeosCryptoApi_CipherHandle*      pCipherHandle,
                      unsigned int                  algorithm,
                      SeosCryptoApi_KeyHandle          key,
                      void*                         iv,
                      size_t                        ivLen)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    *pCipherHandle =
        self->mem.memIf.malloc(sizeof(SeosCryptoCipher));
    seos_rng_t* rng =
        self->mem.memIf.malloc(sizeof(*rng));
    SeosCryptoRng* seosCryptoRng =
        self->mem.memIf.malloc(sizeof(*seosCryptoRng));

    if (NULL == *pCipherHandle || NULL == rng || NULL == seosCryptoRng)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        goto exit;
    }
    else if (seos_rng_init(rng,
                           SeosCrypto_RANDOM_SEED_STR,
                           sizeof(SeosCrypto_RANDOM_SEED_STR) - 1))
    {
        retval = SEOS_ERROR_ABORTED;
        goto err0;
    }
    else
    {
        retval = SeosCryptoRng_init(seosCryptoRng,
                                    rng,
                                    (SeosCryptoRng_ImplRngFunc)
                                    seos_rng_get_prng_bytes);
        if (retval != SEOS_SUCCESS)
        {
            goto err1;
        }
        retval = SeosCryptoCipher_init(*pCipherHandle,
                                       algorithm,
                                       key,
                                       seosCryptoRng,
                                       iv,
                                       ivLen);
        if (retval != SEOS_SUCCESS)
        {
            goto err2;
        }
        else if (!PointerVector_pushBack(&self->cipherHandleVector,
                                         *pCipherHandle))
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
            goto err3;
        }
        else
        {
            goto exit;
        }
    }
err3:
    SeosCryptoCipher_deInit(*pCipherHandle);
err2:
    SeosCryptoRng_deInit(seosCryptoRng);
err1:
    seos_rng_free(rng);
err0:
    self->mem.memIf.free(rng);
    self->mem.memIf.free(seosCryptoRng);
    self->mem.memIf.free(*pCipherHandle);
exit:
    return retval;
}

seos_err_t
SeosCrypto_cipherClose(SeosCryptoApi*           api,
                       SeosCryptoApi_CipherHandle  cipherHandle)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                             cipherHandle);
    if (handlePos != -1)
    {
        SeosCryptoCipher* cipher = cipherHandle;

        SeosCryptoCipher_deInit(cipher);
        SeosCrypto_removeHandle(&self->cipherHandleVector, handlePos);

        SeosCryptoRng_deInit(cipher->rng);
        seos_rng_free(cipher->rng->implCtx);

        self->mem.memIf.free(cipher->rng->implCtx);
        self->mem.memIf.free(cipher->rng);
        self->mem.memIf.free(cipher);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

seos_err_t
SeosCrypto_cipherUpdate(SeosCryptoApi*          api,
                        SeosCryptoApi_CipherHandle cipherHandle,
                        const void*             input,
                        size_t                  inputSize,
                        void**                  output,
                        size_t*                 outputSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

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
SeosCrypto_cipherFinalize(SeosCryptoApi*            api,
                          SeosCryptoApi_CipherHandle   cipherHandle,
                          const void*               input,
                          size_t                    inputSize,
                          void**                    output,
                          size_t*                   outputSize,
                          void**                    tag,
                          size_t*                   tagSize)
{
    SeosCrypto* self = (SeosCrypto*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = SeosCrypto_findHandle(&self->cipherHandleVector,
                                             cipherHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoCipher_finalize(cipherHandle,
                                           input, inputSize,
                                           output, outputSize,
                                           tag, tagSize);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}
