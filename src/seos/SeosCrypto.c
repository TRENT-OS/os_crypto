/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCrypto.h"

#include "LibDebug/Debug.h"
#include "seos_rng.h"

#include "SeosCryptoCipher.h"
#include "SeosCryptoDigest.h"
#include "limits.h"


// Private static functions ----------------------------------------------------

// -1 = not found
static size_t
findHandle(PointerVector* v, Pointer handle)
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
removeHandle(PointerVector* v, size_t pos)
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
        else
        {
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
err0:
    PointerVector_dtor(&self->keyHandleVector);
exit:
    return retval;
}

void
SeosCrypto_deInit(SeosCrypto* self)
{
    PointerVector_dtor(&self->keyHandleVector);
    PointerVector_dtor(&self->digestHandleVector);
}


//-------------------------- Crpyto API functions ------------------------------

seos_err_t
SeosCrypto_getRandomData(SeosCrypto*    self,
                         unsigned int   flags,
                         void const*    saltBuffer,
                         size_t         saltLen,
                         void*          buffer,
                         size_t         bufferLen)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (seos_rng_init(&self->rng,
                      saltBuffer != NULL
                      ? saltBuffer : SeosCrypto_RANDOM_SEED_STR,
                      saltBuffer != NULL
                      ? saltLen : sizeof(SeosCrypto_RANDOM_SEED_STR) - 1 ))
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else
    {
        if (seos_rng_get_prng_bytes(&self->rng, buffer, bufferLen))
        {
            Debug_LOG_DEBUG("%s: aborted", __func__);
            retval = SEOS_ERROR_ABORTED;
        }
        seos_rng_free(&self->rng);
    }
    return retval;
}

seos_err_t
SeosCrypto_digestInit(SeosCrypto*                   self,
                      SeosCrypto_DigestHandle*      pDigestHandle,
                      unsigned                      algorithm,
                      void*                         iv,
                      size_t                        ivLen)
{
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

void
SeosCrypto_digestClose(SeosCrypto*              self,
                       SeosCrypto_DigestHandle  digestHandle)
{
    Debug_ASSERT_SELF(self);

    size_t handlePos = findHandle(&self->digestHandleVector, digestHandle);
    if (handlePos != -1)
    {
        SeosCryptoDigest_deInit(digestHandle);
        removeHandle(&self->digestHandleVector, handlePos);
        self->mem.memIf.free(digestHandle);
    }
}

seos_err_t
SeosCrypto_digestUpdate(SeosCrypto*              self,
                        SeosCrypto_DigestHandle  digestHandle,
                        const void*              data,
                        size_t                   len)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    size_t handlePos = findHandle(&self->digestHandleVector, digestHandle);
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
SeosCrypto_digestFinalize(SeosCrypto*             self,
                          SeosCrypto_DigestHandle digestHandle,
                          const void*             data,
                          size_t                  len,
                          void*                   digest,
                          size_t                  digestSize)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    size_t handlePos = findHandle(&self->digestHandleVector, digestHandle);
    if (handlePos != -1)
    {
        retval = SeosCryptoDigest_finalize2(digestHandle,
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
SeosCrypto_keyGenerate(SeosCrypto*              self,
                       SeosCrypto_KeyHandle*    pKeyHandle,
                       unsigned int             algorithm,
                       unsigned int             flags,
                       size_t                   lenBits)
{
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

            retval = SeosCrypto_getRandomData(self,
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
            Debug_PRINTF("2");
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
SeosCrypto_keyImport(SeosCrypto*            self,
                     SeosCrypto_KeyHandle*  pKeyHandle,
                     unsigned int           algorithm,
                     unsigned int           flags,
                     void const*            keyImportBuffer,
                     size_t                 keyImportLenBits)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == keyImportBuffer)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosCrypto_keyGenerate(self,
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
SeosCrypto_keyExport(SeosCrypto*            self,
                     SeosCrypto_KeyHandle   keyHandle,
                     void*                  buffer,
                     size_t                 bufferLen)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = findHandle(&self->keyHandleVector, keyHandle);
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
SeosCrypto_keyClose(SeosCrypto*             self,
                    SeosCrypto_KeyHandle    keyHandle)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    size_t handlePos = findHandle(&self->keyHandleVector, keyHandle);
    if (handlePos != -1)
    {
        SeosCryptoKey_deInit(keyHandle);
        removeHandle(&self->keyHandleVector, handlePos);
        self->mem.memIf.free(keyHandle);
    }
    else
    {
        retval = SEOS_ERROR_INVALID_HANDLE;
    }
    return retval;
}

// Implement KeyRelease
