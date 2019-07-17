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
        if (self->ivLen != 16 || NULL == self->iv)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
            break;
        }
    case SeosCryptoCipher_Algorithm_AES_EBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_EBC_DEC:
        mbedtls_aes_init(&self->agorithmCtx.aes);
        retval = SEOS_SUCCESS;
        break;

    case SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC:
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC:
        retval = SEOS_SUCCESS;
        break;

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
    case SeosCryptoCipher_Algorithm_AES_EBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_EBC_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        mbedtls_aes_free(&self->agorithmCtx.aes);
        break;
    default:
        break;
    }
}

static seos_err_t
setKeyImpl(SeosCryptoCipher* self)
{
    seos_err_t retval = SEOS_SUCCESS;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_EBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
        retval = mbedtls_aes_setkey_enc(&self->agorithmCtx.aes,
                                        (const unsigned char*) self->key->bytes,
                                        self->key->lenBits) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_AES_EBC_DEC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
        retval = mbedtls_aes_setkey_dec(&self->agorithmCtx.aes,
                                        (const unsigned char*) self->key->bytes,
                                        self->key->lenBits) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC:
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC:
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

static seos_err_t
updateImpl(SeosCryptoCipher* self,
           const char* input,
           size_t inputSize,
           char** output,
           size_t* outputSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoCipher_Algorithm_AES_EBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_EBC_DEC:
    {
        if (inputSize != SeosCryptoCipher_AES_BLOCK_SIZE)
        {
            retval = SEOS_ERROR_INVALID_PARAMETER;
        }
        else
        {
            int mode =
                (self->algorithm == SeosCryptoCipher_Algorithm_AES_EBC_ENC) ?
                MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
            retval = (*outputSize < inputSize)
                     || mbedtls_aes_crypt_ecb(&self->agorithmCtx.aes,
                                              mode,
                                              (unsigned const char*) input,
                                              (unsigned char*) *output) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        }
        *outputSize = inputSize;
    }
    break;

    case SeosCryptoCipher_Algorithm_AES_CBC_ENC:
    case SeosCryptoCipher_Algorithm_AES_CBC_DEC:
    {
//        for (int i = 0; i < SeosCryptoCipher_AES_BLOCK_SIZE; i++)
//            Debug_PRINTF("%s_in -> %x\n", __func__, input[i]);
//        for (int i = 0; i < self->key->lenBits / 8; i++)
//            Debug_PRINTF("%s_key -> %x\n", __func__, self->key->bytes[i]);

        int mode =
            (self->algorithm == SeosCryptoCipher_Algorithm_AES_CBC_ENC) ?
            MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
        retval = (*outputSize < inputSize)
                 || mbedtls_aes_crypt_cbc(&self->agorithmCtx.aes,
                                          mode,
                                          inputSize,
                                          (unsigned char*) self->iv,
                                          (unsigned const char*) input,
                                          (unsigned char*) *output) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        *outputSize = inputSize;

//        for (int i = 0; i < *outputSize; i++)
//            Debug_PRINTF("%s_out -> %x\n", __func__, (*output)[i]);
    }
    break;

    case SeosCryptoCipher_Algorithm_RSA_PKCS1_ENC:
    {
        mbedtls_rsa_context* rsa = (mbedtls_rsa_context*) self->key->algoKeyCtx;

        retval = *outputSize >= rsa->len
                 || mbedtls_rsa_pkcs1_encrypt(self->key->algoKeyCtx,
                                              (int (*)(void*, unsigned char*, size_t)) SeosCryptoRng_nextBytes,
                                              &self->rng,
                                              MBEDTLS_RSA_PUBLIC,
                                              inputSize,
                                              (unsigned const char*) input,
                                              (unsigned char*) output) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }
    case SeosCryptoCipher_Algorithm_RSA_PKCS1_DEC:
    {
        retval = mbedtls_rsa_pkcs1_decrypt(self->key->algoKeyCtx,
                                           (int (*)(void*, unsigned char*, size_t)) SeosCryptoRng_nextBytes,
                                           &self->rng,
                                           MBEDTLS_RSA_PRIVATE,
                                           outputSize,
                                           (unsigned const char*) input,
                                           (unsigned char*) output,
                                           *outputSize) ?
                 SEOS_ERROR_ABORTED : SEOS_SUCCESS;
    }
    break;


    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoCipher_init(SeosCryptoCipher* self,
                      SeosCryptoCipher_Algorithm algorithm,
                      SeosCryptoKey const* key,
                      SeosCryptoRng* rng,
                      char* iv,
                      size_t ivLen)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s: algorithm -> %d", __func__, algorithm);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == key)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm  = algorithm;
    self->key        = key;
    self->iv         = iv;
    self->ivLen      = ivLen;
    self->rng        = rng;

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
SeosCryptoCipher_deInit(SeosCryptoCipher* self)
{
    Debug_ASSERT_SELF(self);

    deInitImpl(self);
}

seos_err_t
SeosCryptoCipher_updateAd(SeosCryptoCipher* self,
                          const char* input,
                          size_t inputSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == input)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        switch (self->algorithm)
        {
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    return retval;
}

seos_err_t
SeosCryptoCipher_update(SeosCryptoCipher* self,
                        const char* input,
                        size_t inputSize,
                        char** output,
                        size_t* outputSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == input || 0 == inputSize || NULL == outputSize)
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
        retval = updateImpl(self, input, inputSize, output, outputSize);

//        Debug_LOG_DEBUG("%s: begin of dump of %d bytes",
//                        __func__, *outputSize);
//        for (int i = 0; i < *outputSize; i++)
//        {
//            Debug_PRINTF(" %02x", (*output)[i]);
//            if ((i + 1) % 16 == 0)
//                Debug_PRINTF("\n");
//        }
    }
    return retval;
}

seos_err_t
SeosCryptoCipher_finalize(SeosCryptoCipher* self,
                          const char* input,
                          size_t inputSize,
                          char** output,
                          size_t* outputSize,
                          char** tag,
                          size_t* tagSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == input || 0 == inputSize
        || NULL == outputSize || NULL == tagSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        switch (self->algorithm)
        {
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    return retval;
}

seos_err_t
SeosCryptoCipher_verifyTag(SeosCryptoCipher* self,
                           char* tag,
                           size_t tagSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == tag)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        switch (self->algorithm)
        {
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
            break;
        }
    }
    return retval;
}
