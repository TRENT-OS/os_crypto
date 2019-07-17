/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoKey.h"
#include "SeosCryptoCipher.h"
#include "SeosCryptoSignature.h"

#include "LibDebug/Debug.h"
#include "mbedtls/rsa.h"

#include <string.h>

// Private static functions ----------------------------------------------------
// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoKey_init(SeosCryptoKey* self,
                   void* algKeyCtx,
                   unsigned algorithm,
                   BitMap16 flags,
                   char* bytes,
                   size_t lenBits)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s: algorithm -> %d, flags -> %x, lenBits -> %zu",
                    __func__, algorithm, flags, lenBits);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == bytes || 0 == lenBits)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memset(self, 0, sizeof(*self));

        switch (algorithm)
        {
        default:
            self->algoKeyCtx    = algKeyCtx;
            self->flags         = flags;
            self->algorithm     = algorithm;
            self->bytes         = bytes;
            self->lenBits       = lenBits;

            retval = SEOS_SUCCESS;

            break;
        }
    }
    return retval;
}

seos_err_t
SeosCryptoKey_initRsaPublic(SeosCryptoKey* self,
                            void* algoKeyCtx,
                            const char* n,
                            size_t lenN,
                            const char* e,
                            size_t lenE)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval           = SEOS_ERROR_GENERIC;
    mbedtls_rsa_context* rsa    = (mbedtls_rsa_context*) algoKeyCtx;

    if (NULL == rsa || NULL == n || NULL == e)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memset(self, 0, sizeof(*self));

        if (mbedtls_rsa_import_raw(rsa,
                                   (unsigned char*) n, lenN,
                                   NULL, 0,
                                   NULL, 0,
                                   NULL, 0,
                                   NULL, 0) != 0
            || mbedtls_rsa_import_raw(rsa,
                                      NULL, 0,
                                      NULL, 0,
                                      NULL, 0,
                                      NULL, 0,
                                      (unsigned char*) e, lenE) != 0
            || mbedtls_rsa_complete(rsa) != 0
            || mbedtls_rsa_check_pubkey(rsa) != 0)
        {
            Debug_LOG_ERROR("%s: failed creating public RSA key", __func__);
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            self->algoKeyCtx = algoKeyCtx;
            self->algorithm  = SeosCryptoSignature_Algorithm_RSA_PKCS1;
            self->lenBits   = rsa->len * CHAR_BIT;

            retval = SEOS_SUCCESS;
        }
    }
    return retval;
}

seos_err_t
SeosCryptoKey_initRsaPrivate(SeosCryptoKey* self,
                             void* algoKeyCtx,
                             const char* n,
                             size_t lenN,
                             const char* e,
                             size_t lenE,
                             const char* d,
                             size_t lenD,
                             const char* p,
                             size_t lenP,
                             const char* q,
                             size_t lenQ)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval           = SEOS_ERROR_GENERIC;
    mbedtls_rsa_context* rsa    = (mbedtls_rsa_context*) algoKeyCtx;

    if (NULL == rsa || NULL == n || NULL == e)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memset(self, 0, sizeof(*self));

        if (mbedtls_rsa_import_raw(rsa,
                                   (unsigned char*) n, lenN,
                                   NULL, 0,
                                   NULL, 0,
                                   NULL, 0,
                                   NULL, 0) != 0
            || mbedtls_rsa_import_raw(rsa,
                                      NULL, 0,
                                      NULL, 0,
                                      NULL, 0,
                                      NULL, 0,
                                      (unsigned char*) e, lenE) != 0
            || mbedtls_rsa_import_raw(rsa,
                                      NULL, 0,
                                      NULL, 0,
                                      NULL, 0,
                                      (unsigned char*) d, lenD,
                                      NULL, 0)
            || mbedtls_rsa_import_raw(rsa,
                                      NULL, 0,
                                      (unsigned char*) p, lenP,
                                      NULL, 0,
                                      NULL, 0,
                                      NULL, 0)
            || mbedtls_rsa_import_raw(rsa,
                                      NULL, 0,
                                      NULL, 0,
                                      (unsigned char*) q, lenQ,
                                      NULL, 0,
                                      NULL, 0 )
            || mbedtls_rsa_complete(rsa) != 0
            || mbedtls_rsa_check_privkey(rsa) != 0)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            self->algoKeyCtx = algoKeyCtx;
            self->algorithm  = SeosCryptoSignature_Algorithm_RSA_PKCS1;
            self->lenBits   = rsa->len * CHAR_BIT;

            retval = SEOS_SUCCESS;
        }
    }
    return retval;
}

void
SeosCryptoKey_deInit(SeosCryptoKey* self)
{
    Debug_ASSERT_SELF(self);

    if (BitMap_GET_BIT(self->flags, SeosCryptoKey_Flags_IS_ALGO_CIPHER))
    {
        // TBD
    }
    else
    {
        switch (self->algorithm)
        {
        case SeosCryptoSignature_Algorithm_RSA_PKCS1:
            mbedtls_rsa_free((mbedtls_rsa_context*) self->algoKeyCtx);
            break;

        default:
            Debug_ASSERT(false);
            break;
        }
    }
}
