/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoCipher.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private static functions ----------------------------------------------------

static seos_err_t
initImpl(SeosCryptoCipher* self)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        if (self->ivLen != SeosCryptoCipher_AES_BLOCK_SIZE)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            mbedtls_aes_init(&self->algorithmCtx.aes);
            retval = SEOS_SUCCESS;
        }
        break;

    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
        mbedtls_aes_init(&self->algorithmCtx.aes);
        retval = SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        if (self->ivLen != SeosCryptoCipher_AES_BLOCK_SIZE)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            mbedtls_gcm_init(&self->algorithmCtx.gcm);
            retval = SEOS_SUCCESS;
        }
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

static void
deInitImpl(SeosCryptoCipher* self)
{
    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        mbedtls_aes_free(&self->algorithmCtx.aes);
        break;

    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        mbedtls_gcm_free(&self->algorithmCtx.gcm);
        break;

    default:
        break;
    }
}

static seos_err_t
setKeyImpl(SeosCryptoCipher* self)
{
    SeosCryptoKey_AES* key = (SeosCryptoKey_AES*)self->key;
    seos_err_t retval = SEOS_SUCCESS;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
        retval = mbedtls_aes_setkey_enc(&self->algorithmCtx.aes,
                                        key->bytes, key->len) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        retval = mbedtls_aes_setkey_dec(&self->algorithmCtx.aes,
                                        key->bytes, key->len) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
        retval = mbedtls_gcm_setkey(&self->algorithmCtx.gcm,
                                    MBEDTLS_CIPHER_ID_AES,
                                    key->bytes, key->len) ?
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
updateImpl(SeosCryptoCipher* self,
           const void* input,
           size_t inputSize,
           void** output,
           size_t* outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    {
        size_t offs;
        int mode =
            (self->algorithm == SeosCryptoCipher_Algorithm_AES_ECB_ENC) ?
            MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;

        if (*outputSize < inputSize || inputSize % SeosCryptoCipher_AES_BLOCK_SIZE)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            retval = SEOS_SUCCESS;
            for (offs = 0; offs < inputSize; offs += SeosCryptoCipher_AES_BLOCK_SIZE)
            {
                if (mbedtls_aes_crypt_ecb(&self->algorithmCtx.aes, mode,
                                          (unsigned const char*) input + offs,
                                          ((unsigned char*) *output) + offs))
                {
                    retval = SEOS_ERROR_ABORTED;
                    break;
                }
            }
        }
        *outputSize = inputSize;
    }
    break;

    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
    {
        int mode =
            (self->algorithm == SeosCryptoCipher_Algorithm_AES_CBC_ENC) ?
            MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
        retval = (*outputSize < inputSize)
                 || (inputSize % SeosCryptoCipher_AES_BLOCK_SIZE)
                 || mbedtls_aes_crypt_cbc(&self->algorithmCtx.aes, mode,
                                          inputSize,
                                          (unsigned char*) self->iv,
                                          (unsigned const char*) input,
                                          (unsigned char*) *output) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        *outputSize = inputSize;
    }
    break;

    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    {
        // mbedtls allows us to feed it an inputSize which is not a multiple of the
        // blocksize ONLY if we do it in the last call before calling finish. Here
        // we check that the user is not calling update after having already fed a
        // non-aligned block.
        retval = (*outputSize < inputSize)
                 || (self->inputLen % SeosCryptoCipher_AES_BLOCK_SIZE)
                 || mbedtls_gcm_update(&self->algorithmCtx.gcm,
                                       inputSize,
                                       (const unsigned char*) input,
                                       (unsigned char*) *output) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        *outputSize = inputSize;
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
    return retval;
}

static seos_err_t
updateAdImpl(SeosCryptoCipher* self,
             const void* ad,
             size_t adLen)
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

    return mbedtls_gcm_starts( &self->algorithmCtx.gcm, mode,
                               self->iv, self->ivLen, ad,
                               adLen ) ?
           SEOS_ERROR_ABORTED : SEOS_SUCCESS;
}

static seos_err_t
finalizeImpl(SeosCryptoCipher* self,
             void**            output,
             size_t*           outputSize)
{
    seos_err_t retval;

    retval = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        // For GCM the last output block is the authentication tag; the maximum
        // size of which is determined by the AES blocksize
        *outputSize = (*outputSize > SeosCryptoCipher_AES_BLOCK_SIZE) ?
                      SeosCryptoCipher_AES_BLOCK_SIZE : *outputSize;
        retval = mbedtls_gcm_finish(&self->algorithmCtx.gcm,
                                    (unsigned char*) *output,
                                    *outputSize) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;

        break;
    case SeosCryptoCipher_Algorithm_AES_ECB_ENC:
    case SeosCryptoCipher_Algorithm_AES_ECB_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        // ECB and CBC can all call finalize as well, but it won't do anything
        // for now; later we may want to apply some padding..
        *outputSize = 0;
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
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
verifyTagImpl(SeosCryptoCipher* self,
              const void*       tag,
              size_t            tagSize)
{
    seos_err_t retval;
    unsigned char check[SeosCryptoCipher_TAG_BUFFER_SIZE];

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_GCM_DEC:
    case SeosCryptoCipher_Algorithm_AES_GCM_ENC:
        retval = mbedtls_gcm_finish(&self->algorithmCtx.gcm, check, tagSize) ||
                 cmemcmp(tag, check, tagSize) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoCipher_init(SeosCrypto_MemIf*             memIf,
                      SeosCryptoCipher*             self,
                      SeosCryptoCipher_Algorithm    algorithm,
                      SeosCryptoKey const*          key,
                      const void*                   iv,
                      size_t                        ivLen)
{
    seos_err_t retval;

    Debug_ASSERT_SELF(self);

    if (NULL == key || ivLen > SeosCryptoCipher_AES_BLOCK_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm  = algorithm;
    self->key        = key;
    self->inputLen   = 0;
    self->ivLen      = ivLen;
    if (NULL != iv)
    {
        memcpy(self->iv, iv, ivLen);
    }

    retval = initImpl(self);
    if (retval != SEOS_SUCCESS)
    {
        goto exit;
    }

    retval = setKeyImpl(self);
    if (retval != SEOS_SUCCESS)
    {
        goto err0;
    }

    goto exit;
err0:
    deInitImpl(self);
exit:
    return retval;
}

void
SeosCryptoCipher_deInit(SeosCrypto_MemIf*   memIf,
                        SeosCryptoCipher*   self)
{
    Debug_ASSERT_SELF(self);

    deInitImpl(self);
}

seos_err_t
SeosCryptoCipher_updateAd(SeosCryptoCipher* self,
                          const void*       input,
                          size_t            inputSize)
{
    seos_err_t retval;

    Debug_ASSERT_SELF(self);

    if (NULL == input || 0 == inputSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = updateAdImpl(self, input, inputSize);
    }
    return retval;
}

seos_err_t
SeosCryptoCipher_update(SeosCryptoCipher*   self,
                        const void*         input,
                        size_t              inputSize,
                        void**              output,
                        size_t*             outputSize)
{
    seos_err_t retval;

    Debug_ASSERT_SELF(self);

    if (NULL == input || 0 == inputSize ||
        NULL == outputSize || NULL == output)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (NULL == *output)
        {
            *output     = self->outputBuf;
            *outputSize = sizeof(self->outputBuf);
        }
        if ((retval = updateImpl(self, input, inputSize, output,
                                 outputSize)) == SEOS_SUCCESS)
        {
            self->inputLen += inputSize;
        }

    }
    return retval;
}

seos_err_t
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          void**            output,
                          size_t*           outputSize)
{
    seos_err_t retval;

    Debug_ASSERT_SELF(self);

    if (NULL == output || NULL == outputSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (NULL == *output)
        {
            *output     = self->outputBuf;
            *outputSize = sizeof(self->outputBuf);
        }
        retval = finalizeImpl(self, output, outputSize);
    }

    return retval;
}

seos_err_t
SeosCryptoCipher_verifyTag(SeosCryptoCipher*    self,
                           const void*          tag,
                           size_t               tagSize)
{
    seos_err_t retval;

    Debug_ASSERT_SELF(self);

    if (NULL == tag)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = verifyTagImpl(self, tag, tagSize);
    }

    return retval;
}