/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoSignature.h"
#include "SeosCryptoKey.h"

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
        mbedtls_rsa_init(&self->mbedtls.rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
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
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
        mbedtls_rsa_free(&self->mbedtls.rsa);
        break;
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
    {
        switch (self->key->type)
        {
        case SeosCryptoKey_Type_RSA_PUBLIC:
        {

            const SeosCryptoKey_RSA_PUBLIC* pubKey = SeosCryptoKey_getRsaPublic(self->key);
            retval = (mbedtls_rsa_import_raw(&self->mbedtls.rsa,
                                             pubKey->nBytes, pubKey->nLen,
                                             NULL, 0,
                                             NULL, 0,
                                             NULL, 0,
                                             pubKey->eBytes, pubKey->eLen) != 0)
                     || (mbedtls_rsa_complete(&self->mbedtls.rsa) != 0)
                     || (mbedtls_rsa_check_pubkey(&self->mbedtls.rsa) != 0) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            break;
        }
        case SeosCryptoKey_Type_RSA_PRIVATE:
        {
            const SeosCryptoKey_RSA_PRIVATE* prvKey = SeosCryptoKey_getRsaPrivate(
                                                          self->key);
            retval = (mbedtls_rsa_import_raw(&self->mbedtls.rsa,
                                             prvKey->nBytes, prvKey->nLen,
                                             prvKey->pBytes, prvKey->pLen,
                                             prvKey->qBytes, prvKey->qLen,
                                             prvKey->dBytes, prvKey->dLen,
                                             NULL, 0) != 0)
                     || (mbedtls_rsa_complete(&self->mbedtls.rsa) != 0)
                     || (mbedtls_rsa_check_privkey(&self->mbedtls.rsa) != 0) ?
                     SEOS_ERROR_ABORTED : SEOS_SUCCESS;
            break;
        }
        default:
            retval = SEOS_ERROR_NOT_SUPPORTED;
        }
        break;
    }
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
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
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
    {
        if (self->key->type != SeosCryptoKey_Type_RSA_PUBLIC)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            if (mbedtls_rsa_pkcs1_verify(&self->mbedtls.rsa,
                                         rngFunc, rng,
                                         MBEDTLS_RSA_PUBLIC,
                                         TO_MBEDTL_MD_ALGO(digestAlgo),
                                         (unsigned int) hashSize,
                                         (const unsigned char*) hash,
                                         (const unsigned char*) signature) != 0)
            {
                retval = SEOS_ERROR_ABORTED;
            }
            else
            {
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

static seos_err_t
signHashImpl(SeosCryptoSignature* self,
             SeosCryptoDigest_Algorithm digestAlgo,
             SeosCryptoRng* rng,
             const char* hash,
             size_t hashSize,
             char* signature,
             size_t* signatureSize)
{
    void* rngFunc = (NULL != rng) ? SeosCryptoRng_getBytesMbedtls : NULL;
    seos_err_t retval = SEOS_ERROR_GENERIC;

    UNUSED_VAR(signatureSize);

    switch (self->algorithm)
    {
    case SeosCryptoSignature_Algorithm_RSA_PKCS1:
    {
        if (self->key->type != SeosCryptoKey_Type_RSA_PRIVATE)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else if (self->mbedtls.rsa.len > *signatureSize)
        {
            retval = SEOS_ERROR_BUFFER_TOO_SMALL;
        }
        else
        {
            if (mbedtls_rsa_pkcs1_sign(&self->mbedtls.rsa,
                                       rngFunc, rng,
                                       MBEDTLS_RSA_PRIVATE,
                                       TO_MBEDTL_MD_ALGO(digestAlgo),
                                       (unsigned int) hashSize,
                                       (const unsigned char*) hash,
                                       (unsigned char*) signature) != 0)
            {
                retval = SEOS_ERROR_ABORTED;
            }
            else
            {
                *signatureSize = self->mbedtls.rsa.len;
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
