/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoAgreement.h"
#include "LibDebug/Debug.h"

#include <string.h>

seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*              self,
                         SeosCryptoAgreement_Algorithm     algorithm) 
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval;

    retval = SEOS_SUCCESS;
    switch (algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        mbedtls_dhm_init(&self->agorithmCtx.dh);
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        mbedtls_ecdh_init(&self->agorithmCtx.ecdh);
        break;
    default:
        retval = SEOS_ERROR_NOT_SUPPORTED;
        break;
    }
    self->algorithm = algorithm;
    return retval;
}


/**
 * @brief closes a key agreement context.
 *
 * @param self (required) pointer to context to free
 *
 */
void
SeosCryptoAgreement_deInit(SeosCryptoAgreement* self)
{
    Debug_ASSERT_SELF(self);

    switch (self->algorithm)
    {
    case SeosCryptoAgreement_Algorithm_DH:
        mbedtls_dhm_free(&self->agorithmCtx.dh);
        break;
    case SeosCryptoAgreement_Algorithm_ECDH:
        mbedtls_ecdh_free(&self->agorithmCtx.ecdh);
        break;
    default:
        break;
    }    
}