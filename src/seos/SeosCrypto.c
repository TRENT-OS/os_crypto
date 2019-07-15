#include "SeosCrypto.h"

#include "LibDebug/Debug.h"
#include "seos_rng.h"

#include "SeosCryptoCipher.h"

seos_err_t
SeosCrypto_init(SeosCrypto* self,
                SeosCrypto_MallocFunc malloc,
                SeosCrypto_FreeFunc free,
                void* bufferCtx,
                size_t* lenBufferCtx)
{
    Debug_ASSERT_SELF(self);
// TBD
    self->mem.memIf.malloc   = malloc;
    self->mem.memIf.free     = free;

    if (seos_rng_init(&self->rng,
                      SeosCrypto_RANDOM_SEED_STR,
                      sizeof(SeosCrypto_RANDOM_SEED_STR) - 1 ))
    {
        return SEOS_ERROR_ABORTED;
    }
    return SEOS_SUCCESS;
}

seos_err_t
SeosCrypto_deInit(SeosCrypto* self)
{
    seos_rng_free(&self->rng);
    return SEOS_SUCCESS;
}

seos_err_t
SeosCrypto_getRandomData(SeosCrypto* self,
                         unsigned int flags,
                         void const* saltBuffer,
                         size_t saltLen,
                         void*   buffer,
                         size_t  bufferLen)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (seos_rng_get_prng_bytes(&self->rng, buffer, bufferLen))
    {
        Debug_LOG_DEBUG("%s: aborted", __func__);
        retval = SEOS_ERROR_ABORTED;
    }
    return retval;
}

seos_err_t
SeosCrypto_keyCreate(SeosCrypto* self,
                     unsigned algorithm,
                     uint16_t flags,
                     size_t lenBits,
                     SeosCrypto_KeyHandle* pKeyHandle,
                     void* keyBlobBuffer,
                     size_t* lenKeyBlobBuffer)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self->mem.memIf.malloc || NULL == self->mem.memIf.free)
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else if (NULL == pKeyHandle || NULL == lenKeyBlobBuffer || !lenBits)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        SeosCryptoKey* pKeyObj = NULL;
        size_t sizeObjBytes = sizeof(SeosCryptoKey) + lenBits / CHAR_BIT;
        sizeObjBytes += (lenBits % CHAR_BIT) ? 1 : 0;

        if (keyBlobBuffer != NULL)
        {
            if (*lenKeyBlobBuffer < sizeObjBytes)
            {
                retval = SEOS_ERROR_BUFFER_TOO_SMALL;
            }
            else
            {
                pKeyObj = keyBlobBuffer;
            }
        }
        else
        {
            if (0 == *lenKeyBlobBuffer)
            {
                *lenKeyBlobBuffer = sizeObjBytes;
            }
            else if (-1 == *lenKeyBlobBuffer)
            {
                pKeyObj = self->mem.memIf.malloc(sizeObjBytes);

                if (NULL == pKeyObj)
                {
                    retval = SEOS_ERROR_INSUFFICIENT_SPACE;
                }
                else
                {
                    *pKeyHandle = pKeyObj;
                    *lenKeyBlobBuffer = sizeObjBytes;
                    char* keyBytes
                        = & (((char*) pKeyObj)[sizeof(SeosCryptoKey)]);

                    retval = SeosCrypto_getRandomData(self,
                                                      0,
                                                      NULL,
                                                      0,
                                                      keyBytes,
                                                      sizeObjBytes);
                    if (SEOS_SUCCESS == retval)
                    {
                        retval = SeosCryptoKey_init(*pKeyHandle,
                                                    NULL,
                                                    algorithm,
                                                    flags,
                                                    keyBytes,
                                                    lenBits);
                    }
                }
            }
            else
            {
                retval = SEOS_ERROR_INVALID_PARAMETER;
            }
        }
        *pKeyHandle = pKeyObj;
    }
    return retval;
}


// Implement KeyRelease
