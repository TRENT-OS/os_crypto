/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoCipher.h"
#include "SeosCryptoKey.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private static functions ----------------------------------------------------

static seos_err_t
initImpl(SeosCryptoCipher*          self,
         const SeosCrypto_MemIf*    memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        mbedtls_aes_init(&self->mbedtls.aes);
        retval = SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
        mbedtls_aes_init(&self->mbedtls.aes);
        retval = SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        mbedtls_gcm_init(&self->mbedtls.gcm);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }
    return retval;
}

static seos_err_t
freeImpl(SeosCryptoCipher*          self,
         const SeosCrypto_MemIf*    memIf)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        mbedtls_aes_free(&self->mbedtls.aes);
        retval = SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        mbedtls_gcm_free(&self->mbedtls.gcm);
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

static seos_err_t
setKeyImpl(SeosCryptoCipher* self)
{
    SeosCryptoKey_AES* aesKey;
    seos_err_t retval = SEOS_SUCCESS;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
        if (SeosCryptoKey_Type_AES != self->key->type ||
            (aesKey = SeosCryptoKey_getAES(self->key)) == NULL)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
        retval = mbedtls_aes_setkey_enc(&self->mbedtls.aes,
                                        aesKey->bytes, aesKey->len * 8) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        retval = mbedtls_aes_setkey_dec(&self->mbedtls.aes,
                                        aesKey->bytes, aesKey->len * 8) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
        retval = mbedtls_gcm_setkey(&self->mbedtls.gcm,
                                    MBEDTLS_CIPHER_ID_AES,
                                    aesKey->bytes, aesKey->len * 8) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

static seos_err_t
setIvImpl(SeosCryptoCipher* self,
          const void*       iv,
          const size_t      ivLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        retval = (iv == NULL || ivLen != SeosCryptoCipher_AES_CBC_IV_SIZE) ?
                 SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
        retval = (ivLen != 0) ? SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
        // We only support 96 bits of IV for GCM
        retval = (iv == NULL || ivLen == 0) ? SEOS_ERROR_INVALID_PARAMETER :
                 (ivLen != SeosCryptoCipher_AES_GCM_IV_SIZE) ? SEOS_ERROR_NOT_SUPPORTED :
                 SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (ivLen > 0 && retval == SEOS_SUCCESS)
    {
        self->ivLen = ivLen;
        memcpy(self->iv, iv, ivLen);
    }

    return retval;
}

static seos_err_t
processImpl(SeosCryptoCipher*    self,
            const void*          input,
            const size_t         inputSize,
            void*                output,
            size_t*              outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (*outputSize < inputSize)
    {
        retval = SEOS_ERROR_BUFFER_TOO_SMALL;
    }
    else
    {
        switch (self->algorithm)
        {
        case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
        case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
            if  (inputSize % SeosCryptoCipher_AES_BLOCK_SIZE)
            {
                retval = SEOS_ERROR_INVALID_PARAMETER;
            }
            else
            {
                size_t offs;
                int mode = (self->algorithm == SeosCryptoCipher_Algorithm_AES_ECB_ENC) ?
                           MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
                retval = SEOS_SUCCESS;
                for (offs = 0; offs < inputSize; offs += SeosCryptoCipher_AES_BLOCK_SIZE)
                {
                    if (mbedtls_aes_crypt_ecb(&self->mbedtls.aes, mode, input + offs,
                                              output + offs) != 0)
                    {
                        retval = SEOS_ERROR_ABORTED;
                        break;
                    }
                }
            }
            break;
        case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
        case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
            if (inputSize % SeosCryptoCipher_AES_BLOCK_SIZE)
            {
                retval = SEOS_ERROR_INVALID_PARAMETER;
            }
            else
            {
                int mode = (self->algorithm == SeosCryptoCipher_Algorithm_AES_CBC_ENC) ?
                           MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
                retval = mbedtls_aes_crypt_cbc(&self->mbedtls.aes, mode, inputSize,
                                               self->ivLen > 0 ? self->iv : NULL, input, output) ?
                         SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            }
            break;
        case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
            // mbedtls allows us to feed it an inputSize which is not a multiple of the
            // blocksize ONLY if we do it in the last call before calling finish. Here
            // we check that the user is not calling update after having already fed a
            // non-aligned block.
            retval = (self->inputLen % SeosCryptoCipher_AES_BLOCK_SIZE) ||
                     !self->started || self->finalized ||
                     mbedtls_gcm_update(&self->mbedtls.gcm, inputSize, input,
                                        output) ? SEOS_ERROR_ABORTED : SEOS_SUCCESS;

            break;
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
        }
    }

    if (SEOS_SUCCESS == retval || SEOS_ERROR_BUFFER_TOO_SMALL == retval)
    {
        // Set output size also if the input size was too small, so user can
        // learn and adjust.
        *outputSize = inputSize;
    }

    return retval;
}

static seos_err_t
startImpl(SeosCryptoCipher* self,
          const void*       ad,
          const size_t      adLen)
{
    int mode;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        mode = MBEDTLS_GCM_ENCRYPT;
        break;
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
        mode = MBEDTLS_GCM_DECRYPT;
        break;
    default:
        return SEOS_ERROR_ABORTED;
    }

    return self->started || self->processed || self->finalized ||
           mbedtls_gcm_starts(&self->mbedtls.gcm, mode, self->iv, self->ivLen,
                              adLen > 0 ? ad : NULL, adLen) != 0 ?
           SEOS_ERROR_ABORTED : SEOS_SUCCESS;
}

/* Compare the contents of two buffers in constant time.
 * Returns 0 if the contents are bitwise identical, otherwise returns
 * a non-zero value.
 */
static int
cmemcmp(const void* v1,
        const void* v2,
        size_t      len)
{
    const unsigned char* p1 = (const unsigned char*) v1;
    const unsigned char* p2 = (const unsigned char*) v2;
    size_t i;
    unsigned char diff;

    for (diff = 0, i = 0; i < len; i++ )
    {
        diff |= p1[i] ^ p2[i];
    }

    return ((int)diff);
}

static seos_err_t
finalizeImpl(SeosCryptoCipher* self,
             void*             buf,
             size_t*           bufSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    {
        unsigned char check[SeosCryptoCipher_AES_GCM_TAG_SIZE];
        // Recompute the tag and compare it; bufSize is used here as INPUT param,
        // so we can compare at least TAG_SIZE bytes, but it can also be less
        retval = (*bufSize > SeosCryptoCipher_AES_GCM_TAG_SIZE) ||
                 !self->started || !self->processed || self->finalized ||
                 mbedtls_gcm_finish(&self->mbedtls.gcm, check, *bufSize) != 0 ||
                 cmemcmp(buf, check, *bufSize) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    {
        if (*bufSize < 4)
        {
            // Tag length must be at least 4!
            *bufSize = 4;
            return SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        // For GCM the last buf block is the authentication tag; the maximum
        // size of which is determined by the AES blocksize
        *bufSize = (*bufSize > SeosCryptoCipher_AES_BLOCK_SIZE) ?
                   SeosCryptoCipher_AES_BLOCK_SIZE : *bufSize;
        retval = !self->started || !self->processed || self->finalized ||
                 mbedtls_gcm_finish(&self->mbedtls.gcm, buf, *bufSize) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
    }

    return retval;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoCipher_init(SeosCryptoCipher*                 self,
                      const SeosCrypto_MemIf*           memIf,
                      const SeosCryptoCipher_Algorithm  algorithm,
                      const SeosCryptoKey*              key,
                      const void*                       iv,
                      const size_t                      ivLen)
{
    seos_err_t retval;

    if (NULL == memIf || NULL == self || NULL == key)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm  = algorithm;
    self->key        = key;
    self->inputLen   = 0;
    // Use these to keep track that everything is being called in proper order
    self->started    = false;
    self->processed    = false;
    self->finalized  = false;

    if ((retval = initImpl(self, memIf)) != SEOS_SUCCESS)
    {
        return retval;
    }

    if ((retval = setIvImpl(self, iv, ivLen)) != SEOS_SUCCESS
        || (retval = setKeyImpl(self)) != SEOS_SUCCESS)
    {
        goto err0;
    }

    return SEOS_SUCCESS;

err0:
    freeImpl(self, memIf);
    return retval;
}

seos_err_t
SeosCryptoCipher_free(SeosCryptoCipher*         self,
                      const SeosCrypto_MemIf*   memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoCipher_start(SeosCryptoCipher*    self,
                       const void*          input,
                       const size_t         inputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = startImpl(self, input, inputSize);
    self->started |= (SEOS_SUCCESS == retval);

    return retval;
}

seos_err_t
SeosCryptoCipher_process(SeosCryptoCipher*   self,
                         const void*         input,
                         const size_t        inputSize,
                         void*               output,
                         size_t*             outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == input || 0 == inputSize || NULL == output
        || NULL == outputSize || 0 == *outputSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((retval = processImpl(self, input, inputSize, output,
                                   outputSize)) == SEOS_SUCCESS)
    {
        self->inputLen += inputSize;
        self->processed = true;
    }

    return retval;
}

seos_err_t
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          void*             buf,
                          size_t*           bufSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == buf || NULL == bufSize || 0 == *bufSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = finalizeImpl(self, buf, bufSize);
    self->finalized |= (SEOS_SUCCESS == retval);

    return retval;
}