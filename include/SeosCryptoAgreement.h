/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoAgreement.h
 *
 * @brief KeyAgreement functions and context
 *
 */
#pragma once

#include "compiler.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

#include "seos_err.h"

typedef enum
{
    SeosCryptoAgreement_Algorithm_DH,
    SeosCryptoAgreement_Algorithm_ECDH
}
SeosCryptoAgreement_Algorithm;

typedef struct
{
    SeosCryptoAgreement_Algorithm algorithm;
    union
    {
        mbedtls_dhm_context     dh;
        mbedtls_ecdh_context    ecdh;
    }
    agorithmCtx;

}
SeosCryptoAgreement;

/**
 * @brief initializes a key agreement context
 *
 * @param self (required) pointer to context to initialize
 * @param algorithm the key agreement algorithm
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing
 * @retval SEOS_ERROR_NOT_SUPPORTED if there is no implementation for the given
 *  algorithm
 *
 */
seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*              self,
                         SeosCryptoAgreement_Algorithm     algorithm);


/**
 * @brief closes a key agreement context.
 *
 * @param self (required) pointer to context to free
 *
 */
void
SeosCryptoAgreement_deInit(SeosCryptoAgreement* self);