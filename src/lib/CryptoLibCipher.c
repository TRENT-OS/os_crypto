/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/CryptoLibCipher.h"

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include <stdbool.h>
#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct CryptoLibCipher
{
    union
    {
        mbedtls_aes_context aes;
        mbedtls_gcm_context gcm;
    } mbedtls;
    OS_CryptoCipher_Alg_t algorithm;
    const CryptoLibKey_t* key;
    uint8_t iv[OS_CryptoCipher_SIZE_AES_BLOCK];
    size_t ivLen;
    size_t inputLen;
    bool started;
    bool processed;
    bool finalized;
};

// Private static functions ----------------------------------------------------

static OS_Error_t
initImpl(
    CryptoLibCipher_t**         self,
    const CryptoLibKey_t*       key,
    const OS_CryptoCipher_Alg_t algorithm,
    const OS_Crypto_Memory_t*   memory)
{
    CryptoLibCipher_t* ciph;
    OS_Error_t err;

    if ((ciph = memory->calloc(1, sizeof(CryptoLibCipher_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(ciph, 0, sizeof(CryptoLibCipher_t));
    ciph->algorithm  = algorithm;
    ciph->key        = key;
    ciph->inputLen   = 0;
    // Use these to keep track that everything is being called in proper order
    ciph->started    = false;
    ciph->processed  = false;
    ciph->finalized  = false;

    err = SEOS_SUCCESS;
    switch (ciph->algorithm)
    {
    case OS_CryptoCipher_ALG_AES_CBC_ENC:
    case OS_CryptoCipher_ALG_AES_CBC_DEC:
        mbedtls_aes_init(&ciph->mbedtls.aes);
        break;
    case OS_CryptoCipher_ALG_AES_ECB_ENC:
    case OS_CryptoCipher_ALG_AES_ECB_DEC:
        mbedtls_aes_init(&ciph->mbedtls.aes);
        break;
    case OS_CryptoCipher_ALG_AES_GCM_DEC:
    case OS_CryptoCipher_ALG_AES_GCM_ENC:
        mbedtls_gcm_init(&ciph->mbedtls.gcm);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (err != SEOS_SUCCESS)
    {
        memory->free(ciph);
    }

    *self = ciph;

    return err;
}

static OS_Error_t
freeImpl(
    CryptoLibCipher_t*        self,
    const OS_Crypto_Memory_t* memory)
{
    OS_Error_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case OS_CryptoCipher_ALG_AES_ECB_ENC:
    case OS_CryptoCipher_ALG_AES_ECB_DEC:
    case OS_CryptoCipher_ALG_AES_CBC_ENC:
    case OS_CryptoCipher_ALG_AES_CBC_DEC:
        mbedtls_aes_free(&self->mbedtls.aes);
        break;
    case OS_CryptoCipher_ALG_AES_GCM_DEC:
    case OS_CryptoCipher_ALG_AES_GCM_ENC:
        mbedtls_gcm_free(&self->mbedtls.gcm);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    memory->free(self);

    return err;
}

static OS_Error_t
setKeyImpl(
    CryptoLibCipher_t* self)
{
    OS_CryptoKey_Aes_t* aesKey;
    OS_Error_t err = SEOS_SUCCESS;

    switch (self->algorithm)
    {
    case OS_CryptoCipher_ALG_AES_ECB_ENC:
    case OS_CryptoCipher_ALG_AES_CBC_ENC:
    case OS_CryptoCipher_ALG_AES_ECB_DEC:
    case OS_CryptoCipher_ALG_AES_CBC_DEC:
    case OS_CryptoCipher_ALG_AES_GCM_ENC:
    case OS_CryptoCipher_ALG_AES_GCM_DEC:
        if (CryptoLibKey_getType(self->key) != OS_CryptoKey_TYPE_AES ||
            (aesKey = CryptoLibKey_getAes(self->key)) == NULL)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    switch (self->algorithm)
    {
    case OS_CryptoCipher_ALG_AES_ECB_ENC:
    case OS_CryptoCipher_ALG_AES_CBC_ENC:
        err = mbedtls_aes_setkey_enc(&self->mbedtls.aes,
                                     aesKey->bytes, aesKey->len * 8) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case OS_CryptoCipher_ALG_AES_ECB_DEC:
    case OS_CryptoCipher_ALG_AES_CBC_DEC:
        err = mbedtls_aes_setkey_dec(&self->mbedtls.aes,
                                     aesKey->bytes, aesKey->len * 8) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case OS_CryptoCipher_ALG_AES_GCM_ENC:
    case OS_CryptoCipher_ALG_AES_GCM_DEC:
        err = mbedtls_gcm_setkey(&self->mbedtls.gcm,
                                 MBEDTLS_CIPHER_ID_AES,
                                 aesKey->bytes, aesKey->len * 8) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

static OS_Error_t
setIvImpl(
    CryptoLibCipher_t* self,
    const void*        iv,
    const size_t       ivSize)
{
    OS_Error_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoCipher_ALG_AES_CBC_ENC:
    case OS_CryptoCipher_ALG_AES_CBC_DEC:
        err = (iv == NULL || ivSize != OS_CryptoCipher_SIZE_AES_CBC_IV) ?
              SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    case OS_CryptoCipher_ALG_AES_ECB_ENC:
    case OS_CryptoCipher_ALG_AES_ECB_DEC:
        err = (ivSize != 0) ? SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    case OS_CryptoCipher_ALG_AES_GCM_ENC:
    case OS_CryptoCipher_ALG_AES_GCM_DEC:
        // We only support 96 bits of IV for GCM
        err = (iv == NULL || ivSize == 0) ? SEOS_ERROR_INVALID_PARAMETER :
              (ivSize != OS_CryptoCipher_SIZE_AES_GCM_IV) ? SEOS_ERROR_NOT_SUPPORTED :
              SEOS_SUCCESS;
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (ivSize > 0 && err == SEOS_SUCCESS)
    {
        self->ivLen = ivSize;
        memcpy(self->iv, iv, ivSize);
    }

    return err;
}

static OS_Error_t
processImpl(
    CryptoLibCipher_t* self,
    const void*        input,
    const size_t       inputSize,
    void*              output,
    size_t*            outputSize)
{
    OS_Error_t err = SEOS_ERROR_GENERIC;

    if (*outputSize < inputSize)
    {
        err = SEOS_ERROR_BUFFER_TOO_SMALL;
    }
    else
    {
        switch (self->algorithm)
        {
        case OS_CryptoCipher_ALG_AES_ECB_ENC:
        case OS_CryptoCipher_ALG_AES_ECB_DEC:
            if  (inputSize % OS_CryptoCipher_SIZE_AES_BLOCK)
            {
                err = SEOS_ERROR_INVALID_PARAMETER;
            }
            else
            {
                size_t offs;
                int mode = (self->algorithm == OS_CryptoCipher_ALG_AES_ECB_ENC) ?
                           MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
                err = SEOS_SUCCESS;
                for (offs = 0; offs < inputSize; offs += OS_CryptoCipher_SIZE_AES_BLOCK)
                {
                    if (mbedtls_aes_crypt_ecb(&self->mbedtls.aes, mode, input + offs,
                                              output + offs) != 0)
                    {
                        err = SEOS_ERROR_ABORTED;
                        break;
                    }
                }
            }
            break;
        case OS_CryptoCipher_ALG_AES_CBC_ENC:
        case OS_CryptoCipher_ALG_AES_CBC_DEC:
            if (inputSize % OS_CryptoCipher_SIZE_AES_BLOCK)
            {
                err = SEOS_ERROR_INVALID_PARAMETER;
            }
            else
            {
                int mode = (self->algorithm == OS_CryptoCipher_ALG_AES_CBC_ENC) ?
                           MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
                err = mbedtls_aes_crypt_cbc(&self->mbedtls.aes, mode, inputSize,
                                            self->ivLen > 0 ? self->iv : NULL, input, output) ?
                      SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            }
            break;
        case OS_CryptoCipher_ALG_AES_GCM_ENC:
        case OS_CryptoCipher_ALG_AES_GCM_DEC:
            // mbedtls allows us to feed it an inputSize which is not a multiple of the
            // blocksize ONLY if we do it in the last call before calling finish. Here
            // we check that the user is not calling update after having already fed a
            // non-aligned block.
            err = (self->inputLen % OS_CryptoCipher_SIZE_AES_BLOCK) ||
                  !self->started || self->finalized ||
                  mbedtls_gcm_update(&self->mbedtls.gcm, inputSize, input,
                                     output) ? SEOS_ERROR_ABORTED : SEOS_SUCCESS;

            break;
        default:
            err = SEOS_ERROR_NOT_SUPPORTED;
        }
    }

    if (SEOS_SUCCESS == err || SEOS_ERROR_BUFFER_TOO_SMALL == err)
    {
        // Set output size also if the input size was too small, so user can
        // learn and adjust.
        *outputSize = inputSize;
    }

    return err;
}

static OS_Error_t
startImpl(
    CryptoLibCipher_t* self,
    const void*        ad,
    const size_t       adSize)
{
    int mode;

    switch (self->algorithm)
    {
    case OS_CryptoCipher_ALG_AES_GCM_ENC:
        mode = MBEDTLS_GCM_ENCRYPT;
        break;
    case OS_CryptoCipher_ALG_AES_GCM_DEC:
        mode = MBEDTLS_GCM_DECRYPT;
        break;
    default:
        return SEOS_ERROR_ABORTED;
    }

    return self->started || self->processed || self->finalized ||
           mbedtls_gcm_starts(&self->mbedtls.gcm, mode, self->iv, self->ivLen,
                              adSize > 0 ? ad : NULL, adSize) != 0 ?
           SEOS_ERROR_ABORTED : SEOS_SUCCESS;
}

/* Compare the contents of two buffers in constant time.
 * Returns 0 if the contents are bitwise identical, otherwise returns
 * a non-zero value.
 */
static int
cmemcmp(
    const void* v1,
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

static OS_Error_t
finalizeImpl(
    CryptoLibCipher_t* self,
    void*              buf,
    size_t*            bufSize)
{
    OS_Error_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case OS_CryptoCipher_ALG_AES_GCM_DEC:
    {
        unsigned char check[OS_CryptoCipher_SIZE_AES_GCM_TAG_MAX];

        if (*bufSize < OS_CryptoCipher_SIZE_AES_GCM_TAG_MIN)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        // Recompute the tag and compare it; bufSize is used here as INPUT param,
        // so we can compare at least TAG_SIZE bytes, but it can also be less
        err = (*bufSize > OS_CryptoCipher_SIZE_AES_GCM_TAG_MAX) ||
              !self->started || !self->processed || self->finalized ||
              mbedtls_gcm_finish(&self->mbedtls.gcm, check, *bufSize) != 0 ||
              cmemcmp(buf, check, *bufSize) != 0 ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    case OS_CryptoCipher_ALG_AES_GCM_ENC:
    {
        if (*bufSize < OS_CryptoCipher_SIZE_AES_GCM_TAG_MIN)
        {
            // We have a minimum tag length
            *bufSize = OS_CryptoCipher_SIZE_AES_GCM_TAG_MIN;
            return SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        // For GCM the last buf block is the authentication tag; the maximum
        // size of which is determined by the AES blocksize
        *bufSize = (*bufSize > OS_CryptoCipher_SIZE_AES_BLOCK) ?
                   OS_CryptoCipher_SIZE_AES_BLOCK : *bufSize;
        err = !self->started || !self->processed || self->finalized ||
              mbedtls_gcm_finish(&self->mbedtls.gcm, buf, *bufSize) != 0 ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    return err;
}

// Public functions ------------------------------------------------------------

OS_Error_t
CryptoLibCipher_init(
    CryptoLibCipher_t**         self,
    const CryptoLibKey_t*       key,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    const size_t                ivSize,
    const OS_Crypto_Memory_t*   memory)
{
    OS_Error_t err;

    if (NULL == memory || NULL == self || NULL == key)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = initImpl(self, key, algorithm, memory)) == SEOS_SUCCESS)
    {
        if ((err = setIvImpl(*self, iv, ivSize)) != SEOS_SUCCESS
            || (err = setKeyImpl(*self)) != SEOS_SUCCESS)
        {
            freeImpl(*self, memory);
        }
    }

    return err;
}

OS_Error_t
CryptoLibCipher_free(
    CryptoLibCipher_t*        self,
    const OS_Crypto_Memory_t* memory)
{
    if (NULL == memory || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memory);
}

OS_Error_t
CryptoLibCipher_start(
    CryptoLibCipher_t* self,
    const void*        input,
    const size_t       inputSize)
{
    OS_Error_t err = SEOS_ERROR_GENERIC;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = startImpl(self, input, inputSize);
    self->started |= (SEOS_SUCCESS == err);

    return err;
}

OS_Error_t
CryptoLibCipher_process(
    CryptoLibCipher_t* self,
    const void*        input,
    const size_t       inputSize,
    void*              output,
    size_t*            outputSize)
{
    OS_Error_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == input || 0 == inputSize || NULL == output
        || NULL == outputSize || 0 == *outputSize)
    {
        err = SEOS_ERROR_INVALID_PARAMETER;
    }
    else if ((err = processImpl(self, input, inputSize, output,
                                outputSize)) == SEOS_SUCCESS)
    {
        self->inputLen += inputSize;
        self->processed = true;
    }

    return err;
}

OS_Error_t
CryptoLibCipher_finalize(
    CryptoLibCipher_t* self,
    void*              buf,
    size_t*            bufSize)
{
    OS_Error_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == buf || NULL == bufSize || 0 == *bufSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = finalizeImpl(self, buf, bufSize);
    self->finalized |= (SEOS_SUCCESS == err);

    return err;
}