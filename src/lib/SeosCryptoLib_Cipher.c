/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "lib/SeosCryptoLib_Cipher.h"

#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include <stdbool.h>
#include <string.h>

// Internal types/defines/enums ------------------------------------------------

struct SeosCryptoLib_Cipher
{
    union
    {
        mbedtls_aes_context aes;
        mbedtls_rsa_context rsa;
        mbedtls_gcm_context gcm;
    }
    mbedtls;
    SeosCryptoApi_Cipher_Alg algorithm;
    const SeosCryptoLib_Key* key;
    uint8_t iv[SeosCryptoApi_Cipher_SIZE_AES_BLOCK];
    size_t ivLen;
    size_t inputLen;
    bool started;
    bool processed;
    bool finalized;
};

// Private static functions ----------------------------------------------------

static seos_err_t
initImpl(
    SeosCryptoLib_Cipher**         self,
    const SeosCryptoApi_MemIf*     memIf,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       key)
{
    SeosCryptoLib_Cipher* ciph;
    seos_err_t err;

    if ((ciph = memIf->malloc(sizeof(SeosCryptoLib_Cipher))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(ciph, 0, sizeof(SeosCryptoLib_Cipher));
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
    case SeosCryptoApi_Cipher_ALG_AES_CBC_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_DEC:
        mbedtls_aes_init(&ciph->mbedtls.aes);
        break;
    case SeosCryptoApi_Cipher_ALG_AES_ECB_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_ECB_DEC:
        mbedtls_aes_init(&ciph->mbedtls.aes);
        break;
    case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
    case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
        mbedtls_gcm_init(&ciph->mbedtls.gcm);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (err != SEOS_SUCCESS)
    {
        memIf->free(ciph);
    }

    *self = ciph;

    return err;
}

static seos_err_t
freeImpl(
    SeosCryptoLib_Cipher*      self,
    const SeosCryptoApi_MemIf* memIf)
{
    seos_err_t err;

    err = SEOS_SUCCESS;
    switch (self->algorithm)
    {
    case SeosCryptoApi_Cipher_ALG_AES_ECB_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_ECB_DEC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_DEC:
        mbedtls_aes_free(&self->mbedtls.aes);
        break;
    case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
    case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
        mbedtls_gcm_free(&self->mbedtls.gcm);
        break;
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    memIf->free(self);

    return err;
}

static seos_err_t
setKeyImpl(
    SeosCryptoLib_Cipher* self)
{
    SeosCryptoApi_Key_Aes* aesKey;
    seos_err_t err = SEOS_SUCCESS;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Cipher_ALG_AES_ECB_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_ECB_DEC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_DEC:
    case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
        if (SeosCryptoLib_Key_getType(self->key) != SeosCryptoApi_Key_TYPE_AES ||
            (aesKey = SeosCryptoLib_Key_getAes(self->key)) == NULL)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        break;
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    switch (self->algorithm)
    {
    case SeosCryptoApi_Cipher_ALG_AES_ECB_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_ENC:
        err = mbedtls_aes_setkey_enc(&self->mbedtls.aes,
                                     aesKey->bytes, aesKey->len * 8) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Cipher_ALG_AES_ECB_DEC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_DEC:
        err = mbedtls_aes_setkey_dec(&self->mbedtls.aes,
                                     aesKey->bytes, aesKey->len * 8) ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
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

static seos_err_t
setIvImpl(
    SeosCryptoLib_Cipher* self,
    const void*           iv,
    const size_t          ivSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Cipher_ALG_AES_CBC_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_CBC_DEC:
        err = (iv == NULL || ivSize != SeosCryptoApi_Cipher_SIZE_AES_CBC_IV) ?
              SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Cipher_ALG_AES_ECB_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_ECB_DEC:
        err = (ivSize != 0) ? SEOS_ERROR_INVALID_PARAMETER : SEOS_SUCCESS;
        break;
    case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
    case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
        // We only support 96 bits of IV for GCM
        err = (iv == NULL || ivSize == 0) ? SEOS_ERROR_INVALID_PARAMETER :
              (ivSize != SeosCryptoApi_Cipher_SIZE_AES_GCM_IV) ? SEOS_ERROR_NOT_SUPPORTED :
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

static seos_err_t
processImpl(
    SeosCryptoLib_Cipher* self,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (*outputSize < inputSize)
    {
        err = SEOS_ERROR_BUFFER_TOO_SMALL;
    }
    else
    {
        switch (self->algorithm)
        {
        case SeosCryptoApi_Cipher_ALG_AES_ECB_ENC:
        case SeosCryptoApi_Cipher_ALG_AES_ECB_DEC:
            if  (inputSize % SeosCryptoApi_Cipher_SIZE_AES_BLOCK)
            {
                err = SEOS_ERROR_INVALID_PARAMETER;
            }
            else
            {
                size_t offs;
                int mode = (self->algorithm == SeosCryptoApi_Cipher_ALG_AES_ECB_ENC) ?
                           MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
                err = SEOS_SUCCESS;
                for (offs = 0; offs < inputSize; offs += SeosCryptoApi_Cipher_SIZE_AES_BLOCK)
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
        case SeosCryptoApi_Cipher_ALG_AES_CBC_ENC:
        case SeosCryptoApi_Cipher_ALG_AES_CBC_DEC:
            if (inputSize % SeosCryptoApi_Cipher_SIZE_AES_BLOCK)
            {
                err = SEOS_ERROR_INVALID_PARAMETER;
            }
            else
            {
                int mode = (self->algorithm == SeosCryptoApi_Cipher_ALG_AES_CBC_ENC) ?
                           MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
                err = mbedtls_aes_crypt_cbc(&self->mbedtls.aes, mode, inputSize,
                                            self->ivLen > 0 ? self->iv : NULL, input, output) ?
                      SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            }
            break;
        case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
        case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
            // mbedtls allows us to feed it an inputSize which is not a multiple of the
            // blocksize ONLY if we do it in the last call before calling finish. Here
            // we check that the user is not calling update after having already fed a
            // non-aligned block.
            err = (self->inputLen % SeosCryptoApi_Cipher_SIZE_AES_BLOCK) ||
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

static seos_err_t
startImpl(
    SeosCryptoLib_Cipher* self,
    const void*           ad,
    const size_t          adSize)
{
    int mode;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
        mode = MBEDTLS_GCM_ENCRYPT;
        break;
    case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
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

static seos_err_t
finalizeImpl(
    SeosCryptoLib_Cipher* self,
    void*                 buf,
    size_t*               bufSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoApi_Cipher_ALG_AES_GCM_DEC:
    {
        unsigned char check[SeosCryptoApi_Cipher_SIZE_AES_GCM_TAG_MAX];

        if (*bufSize < SeosCryptoApi_Cipher_SIZE_AES_GCM_TAG_MIN)
        {
            return SEOS_ERROR_INVALID_PARAMETER;
        }
        // Recompute the tag and compare it; bufSize is used here as INPUT param,
        // so we can compare at least TAG_SIZE bytes, but it can also be less
        err = (*bufSize > SeosCryptoApi_Cipher_SIZE_AES_GCM_TAG_MAX) ||
              !self->started || !self->processed || self->finalized ||
              mbedtls_gcm_finish(&self->mbedtls.gcm, check, *bufSize) != 0 ||
              cmemcmp(buf, check, *bufSize) != 0 ?
              SEOS_ERROR_ABORTED : SEOS_SUCCESS;
        break;
    }
    case SeosCryptoApi_Cipher_ALG_AES_GCM_ENC:
    {
        if (*bufSize < SeosCryptoApi_Cipher_SIZE_AES_GCM_TAG_MIN)
        {
            // We have a minimum tag length
            *bufSize = SeosCryptoApi_Cipher_SIZE_AES_GCM_TAG_MIN;
            return SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        // For GCM the last buf block is the authentication tag; the maximum
        // size of which is determined by the AES blocksize
        *bufSize = (*bufSize > SeosCryptoApi_Cipher_SIZE_AES_BLOCK) ?
                   SeosCryptoApi_Cipher_SIZE_AES_BLOCK : *bufSize;
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

seos_err_t
SeosCryptoLib_Cipher_init(
    SeosCryptoLib_Cipher**         self,
    const SeosCryptoApi_MemIf*     memIf,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       key,
    const void*                    iv,
    const size_t                   ivSize)
{
    seos_err_t err;

    if (NULL == memIf || NULL == self || NULL == key)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = initImpl(self, memIf, algorithm, key)) == SEOS_SUCCESS)
    {
        if ((err = setIvImpl(*self, iv, ivSize)) != SEOS_SUCCESS
            || (err = setKeyImpl(*self)) != SEOS_SUCCESS)
        {
            freeImpl(*self, memIf);
        }
    }

    return err;
}

seos_err_t
SeosCryptoLib_Cipher_free(
    SeosCryptoLib_Cipher*      self,
    const SeosCryptoApi_MemIf* memIf)
{
    if (NULL == memIf || NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(self, memIf);
}

seos_err_t
SeosCryptoLib_Cipher_start(
    SeosCryptoLib_Cipher* self,
    const void*           input,
    const size_t          inputSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = startImpl(self, input, inputSize);
    self->started |= (SEOS_SUCCESS == err);

    return err;
}

seos_err_t
SeosCryptoLib_Cipher_process(
    SeosCryptoLib_Cipher* self,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

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

seos_err_t
SeosCryptoLib_Cipher_finalize(
    SeosCryptoLib_Cipher* self,
    void*                 buf,
    size_t*               bufSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == buf || NULL == bufSize || 0 == *bufSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = finalizeImpl(self, buf, bufSize);
    self->finalized |= (SEOS_SUCCESS == err);

    return err;
}