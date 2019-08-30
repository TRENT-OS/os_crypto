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

#include "SeosCryptoRng.h"

#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"

#include "seos_err.h"

typedef enum
{
    SeosCryptoAgreement_Algorithm_NONE,
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
    algCtx;
    SeosCryptoRng*              rng;
    SeosCryptoKey*              privateKey;
}
SeosCryptoAgreement;

/**
 * @brief initializes a key agreement context
 *
 * @param self (required) pointer to context to initialize
 * @param algorithm the key agreement algorithm
 * @param privateKey (required) our private key
 * @param rng (required) random number generator
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
                         SeosCryptoAgreement_Algorithm     algorithm,
                         SeosCryptoKey*                    privateKey,
                         SeosCryptoRng*                    rng);

/**
 * @brief computes a shared secret
 *
 * @param self (required) pointer to context
 * @param publicKey (required) their public key
 * @param buf (required) buffer for resulting shared key
 * @param bufSize size of buffer in bytes
 * @param outLen length of shared key in bytes
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing
 * @retval SEOS_ERROR_ABORTED if calculation could not execute due to small buffers
 *  or other errors
 *
 */
seos_err_t
SeosCryptoAgreement_computeShared(SeosCryptoAgreement*  self,
                                  SeosCryptoKey*        publicKey,
                                  unsigned char*        buf,
                                  size_t                bufSize,
                                  size_t*               outLen);

/**
 * @brief closes a key agreement context.
 *
 * @param self (required) pointer to context to free
 *
 */
void
SeosCryptoAgreement_deInit(SeosCryptoAgreement* self);

/** @} */
