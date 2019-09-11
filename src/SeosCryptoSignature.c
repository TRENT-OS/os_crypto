/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoSignature.h"
#include "LibDebug/Debug.h"

#include <string.h>

#define TO_MBEDTL_MD_ALGO(x)    (x)

// Private Functions -----------------------------------------------------------

static seos_err_t
initImpl(SeosCryptoSignature* self)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        retval = SEOS_SUCCESS;
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

static void
deInitImpl(SeosCryptoSignature* self)
{
    switch (self->algorithm)
    {
    default:
        break;
    }
}

static seos_err_t
setKeyImpl(SeosCryptoSignature* self)
{
    seos_err_t retval = SEOS_SUCCESS;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

//static seos_err_t
//updateImpl(SeosCryptoSignature* self,
//           const char* input,
//           size_t inputSize)
//{
//    seos_err_t retval = SEOS_ERROR_GENERIC;
//
//    switch (self->algorithm)
//    {
//    default:
//        retval = SEOS_ERROR_NOT_SUPPORTED;
//        break;
//    }
//    return retval;
//}

static seos_err_t
verifyHashImpl(SeosCryptoSignature* self,
               SeosCryptoDigest_Algorithm digestAlgo,
               SeosCryptoRng* rng,
               const char* hash,
               size_t hashSize,
               const char* signature,
               size_t signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
    {
        mbedtls_rsa_context* rsa = (mbedtls_rsa_context*) self->key->algoKeyCtx;
        void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytes_mbedtls : NULL;
        if (mbedtls_rsa_pkcs1_verify(rsa,
                                     rngFunc, rng,
                                     MBEDTLS_RSA_PUBLIC,
                                     TO_MBEDTL_MD_ALGO(digestAlgo),
                                     (unsigned int) hashSize,
                                     (const unsigned char*) hash,
                                     (const unsigned char*) signature))
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            retval = SEOS_SUCCESS;
        }
    }
    break;

    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

static seos_err_t
signHashImpl(SeosCryptoSignature* self,
             SeosCryptoDigest_Algorithm digestAlgo,
             SeosCryptoRng* rng,
             const char* hash,
             size_t hashSize,
             char* signature,
             size_t* signatureSize)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;
    UNUSED_VAR(signatureSize);

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
    {
        mbedtls_rsa_context* rsa = (mbedtls_rsa_context*) self->key->algoKeyCtx;

        if (rsa->len > *signatureSize)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytes_mbedtls : NULL;
            int err = mbedtls_rsa_pkcs1_sign(rsa,
                                             rngFunc, rng,
                                             MBEDTLS_RSA_PRIVATE,
                                             TO_MBEDTL_MD_ALGO(digestAlgo),
                                             (unsigned int) hashSize,
                                             (const unsigned char*) hash,
                                             (unsigned char*) signature);
            if (err)
            {
                Debug_LOG_DEBUG("%s: mbedtls_rsa_pkcs1_sign failed with err %d",
                                __func__, err);
                retval = SEOS_ERROR_ABORTED;
            }
            else
            {
                *signatureSize = rsa->len;
                retval = SEOS_SUCCESS;
            }
        }
    }
    break;

    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    return retval;
}

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoSignature_init(SeosCryptoSignature* self,
                         SeosCryptoSignature_Algorithm algorithm,
                         SeosCryptoKey const* key,
                         char* iv,
                         size_t ivLen)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == key)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    memset(self, 0, sizeof(*self));

    self->algorithm  = algorithm;
    self->key        = key;

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
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: failed with err %d", __func__, retval);
    }
    return retval;
}

void
SeosCryptoSignature_deInit(SeosCryptoSignature* self)
{
    Debug_ASSERT_SELF(self);

    deInitImpl(self);
}

//seos_err_t
//SeosCryptoSignature_update(SeosCryptoSignature* self,
//                           const char* data,
//                           size_t len)
//{
//    Debug_ASSERT_SELF(self);
//
//    seos_err_t retval = SEOS_ERROR_GENERIC;
//
//    if (NULL == data || 0 == len)
//    {
//        retval = SEOS_ERROR_INVALID_PARAMETER;
//    }
//    else
//    {
//        retval = updateImpl(self, data, len);
//    }
//    return retval;
//}

seos_err_t
SeosCryptoSignature_sign(SeosCryptoSignature* self,
                         SeosCryptoDigest_Algorithm digestAlgo,
                         SeosCryptoRng* rng,
                         const char* hash,
                         size_t hashSize,
                         char* signature,
                         size_t* signatureSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == signature || NULL == signatureSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = signHashImpl(self,
                              digestAlgo,
                              rng,
                              hash,
                              hashSize,
                              signature,
                              signatureSize);
    }
    return retval;
}

seos_err_t
SeosCryptoSignature_verify(SeosCryptoSignature* self,
                           SeosCryptoDigest_Algorithm digestAlgo,
                           SeosCryptoRng* rng,
                           const char* hash,
                           size_t hashSize,
                           const char* signature,
                           size_t signatureSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == hash || !hashSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = verifyHashImpl(self,
                                digestAlgo,
                                rng,
                                hash,
                                hashSize,
                                signature,
                                signatureSize);
    }
    Debug_LOG_TRACE("%s: returns %d", __func__, retval);
    return retval;
}
