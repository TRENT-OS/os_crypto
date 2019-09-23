/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoCipher.h"
#include "SeosCryptoKey.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private static functions ----------------------------------------------------

static seos_err_t
initImpl(SeosCrypto_MemIf*      memIf,
         SeosCryptoCipher*      self)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        mbedtls_aes_init(&self->algorithmCtx.aes);
        retval = SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
        mbedtls_aes_init(&self->algorithmCtx.aes);
        retval = SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        mbedtls_gcm_init(&self->algorithmCtx.gcm);
        retval = SEOS_SUCCESS;
        break;

#if 0
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC:
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC:
        retval = SEOS_SUCCESS;
        break;
#endif

    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

static seos_err_t
deInitImpl(SeosCrypto_MemIf*    memIf,
           SeosCryptoCipher*    self)
{
    UNUSED_VAR(memIf);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        mbedtls_aes_free(&self->algorithmCtx.aes);
        retval = SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        mbedtls_gcm_free(&self->algorithmCtx.gcm);
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
        if (SeosCryptoKey_Type_AES != self->key->type)
        {
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        else if ((aesKey = SeosCryptoKey_getAES(self->key)) == NULL)
        {
            return SEOS_ERROR_NOT_SUPPORTED;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
        retval = mbedtls_aes_setkey_enc(&self->algorithmCtx.aes,
                                        aesKey->bytes, self->key->bits) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        retval = mbedtls_aes_setkey_dec(&self->algorithmCtx.aes,
                                        aesKey->bytes, self->key->bits) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
        retval = mbedtls_gcm_setkey(&self->algorithmCtx.gcm,
                                    MBEDTLS_CIPHER_ID_AES,
                                    aesKey->bytes, self->key->bits) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;

#if 0
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC:
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC:
        retval = SEOS_SUCCESS;
        break;
#endif

    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

static seos_err_t
setIvImpl(SeosCryptoCipher* self,
          const void*       iv,
          size_t            ivLen)
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
updateImpl(SeosCryptoCipher*    self,
           const void*          input,
           size_t               inputSize,
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
        {
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
                    if (mbedtls_aes_crypt_ecb(&self->algorithmCtx.aes, mode, input + offs,
                                              output + offs) != 0)
                    {
                        retval = SEOS_ERROR_ABORTED;
                        break;
                    }
                }
            }
        }
        break;

        case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
        case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        {
            if (inputSize % SeosCryptoCipher_AES_BLOCK_SIZE)
            {
                retval = SEOS_ERROR_INVALID_PARAMETER;
            }
            else
            {
                int mode = (self->algorithm == SeosCryptoCipher_Algorithm_AES_CBC_ENC) ?
                           MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
                retval = mbedtls_aes_crypt_cbc(&self->algorithmCtx.aes, mode, inputSize,
                                               self->ivLen > 0 ? self->iv : NULL, input, output) ?
                         SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            }
        }
        break;

        case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
        {
            // mbedtls allows us to feed it an inputSize which is not a multiple of the
            // blocksize ONLY if we do it in the last call before calling finish. Here
            // we check that the user is not calling update after having already fed a
            // non-aligned block.
            retval = (self->inputLen % SeosCryptoCipher_AES_BLOCK_SIZE) ||
                     !self->started || self->finalized ||
                     mbedtls_gcm_update(&self->algorithmCtx.gcm, inputSize, input,
                                        output) ? SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;

#if 0
        case SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC:
        {
            mbedtls_rsa_context* rsa = (mbedtls_rsa_context*) self->key->algoKeyCtx;

            retval = *outputSize >= rsa->len
                     || mbedtls_rsa_pkcs1_encrypt(self->key->algoKeyCtx,
                                                  NULL,
                                                  NULL,
                                                  MBEDTLS_RSA_PUBLIC,
                                                  inputSize,
                                                  (unsigned const char*) input,
                                                  (unsigned char*) output) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        case SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC:
        {
            retval = mbedtls_rsa_pkcs1_decrypt(self->key->algoKeyCtx,
                                               NULL,
                                               NULL,
                                               MBEDTLS_RSA_PRIVATE,
                                               outputSize,
                                               (unsigned const char*) input,
                                               (unsigned char*) output,
                                               *outputSize) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        break;
#endif

        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
            break;
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
startImpl(SeosCryptoCipher*     self,
          const void*           ad,
          size_t                adLen)
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
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return self->started || self->updated || self->finalized ||
           mbedtls_gcm_starts(&self->algorithmCtx.gcm, mode, self->iv, self->ivLen,
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
                 !self->started || !self->updated || self->finalized ||
                 mbedtls_gcm_finish(&self->algorithmCtx.gcm, check, *bufSize) != 0 ||
                 cmemcmp(buf, check, *bufSize) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    {
        // For GCM the last buf block is the authentication tag; the maximum
        // size of which is determined by the AES blocksize
        *bufSize = (*bufSize > SeosCryptoCipher_AES_BLOCK_SIZE) ?
                   SeosCryptoCipher_AES_BLOCK_SIZE : *bufSize;
        retval = !self->started || !self->updated || self->finalized ||
                 mbedtls_gcm_finish(&self->algorithmCtx.gcm, buf, *bufSize) != 0 ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }

    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoCipher_init(SeosCrypto_MemIf*              memIf,
                      SeosCryptoCipher*              self,
                      SeosCryptoCipher_Algorithm     algorithm,
                      SeosCryptoKey const*           key,
                      const void*                    iv,
                      size_t                         ivLen)
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
    self->updated    = false;
    self->finalized  = false;

    if ((retval = initImpl(memIf, self)) != SEOS_SUCCESS)
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
    deInitImpl(memIf, self);
    return retval;
}

seos_err_t
SeosCryptoCipher_deInit(SeosCrypto_MemIf*    memIf,
                        SeosCryptoCipher*    self)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return deInitImpl(memIf, self);
}

seos_err_t
SeosCryptoCipher_start(SeosCryptoCipher* self,
                       const void*       input,
                       size_t            inputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    retval = startImpl(self, input, inputSize);
    if (!self->started)
    {
        self->started = (SEOS_SUCCESS == retval);
    }

    return retval;
}

seos_err_t
SeosCryptoCipher_update(SeosCryptoCipher*   self,
                        const void*         input,
                        size_t              inputSize,
                        void*               output,
                        size_t*             outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == input || 0 == inputSize || NULL == output
        || NULL == outputSize || 0 == *outputSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((retval = updateImpl(self, input, inputSize, output,
                                  outputSize)) == SEOS_SUCCESS)
    {
        self->inputLen += inputSize;
        self->updated   = true;
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
    if (!self->finalized)
    {
        self->finalized = (SEOS_SUCCESS == retval);
    }

    return retval;
}