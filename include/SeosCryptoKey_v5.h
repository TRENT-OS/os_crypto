/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoKey_v5.h
 *
 * @brief Key functions and context
 *
 */
#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoKey_Impl_v5.h"

#include "seos_err.h"
#include "compiler.h"

#include <stddef.h>

seos_err_t
SeosCryptoKey_generate_v5(SeosCryptoKey_v5*         self,
                          const SeosCrypto_MemIf*   memIf,
                          SeosCryptoRng*            rng,
                          const SeosCryptoKey_Spec* spec);

seos_err_t
SeosCryptoKey_makePublic_v5(SeosCryptoKey_v5*               self,
                            const SeosCrypto_MemIf*         memIf,
                            const SeosCryptoKey_v5*         prvKey,
                            const SeosCryptoKey_Attribs*    attribs);

seos_err_t
SeosCryptoKey_import_v5(SeosCryptoKey_v5*          self,
                        const SeosCrypto_MemIf*    memIf,
                        const SeosCryptoKey_v5*    wrapKey,
                        const SeosCryptoKey_Data*  keyData);

seos_err_t
SeosCryptoKey_export_v5(SeosCryptoKey_v5*       self,
                        const SeosCryptoKey_v5* wrapKey,
                        SeosCryptoKey_Data*     keyData);

seos_err_t
SeosCryptoKey_getParams_v5(SeosCryptoKey_v5*    self,
                           void*                keyParams,
                           size_t*              paramSize);

seos_err_t
SeosCryptoKey_loadParams_v5(const SeosCryptoKey_Param   name,
                            void*                       keyParams,
                            size_t*                     paramSize);

seos_err_t
SeosCryptoKey_free_v5(SeosCryptoKey_v5*        self,
                      const SeosCrypto_MemIf*  memIf);

/**
 * @brief Writes key data into mbedTLS RSA object
 */
seos_err_t
SeosCryptoKey_writeRSAPub_v5(const SeosCryptoKey_v5* key,
                             mbedtls_rsa_context* rsa);
seos_err_t
SeosCryptoKey_writeRSAPrv_v5(const SeosCryptoKey_v5* key,
                             mbedtls_rsa_context* rsa);

/**
 * @brief Writes key data into mbedTLS DH object
 */
seos_err_t
SeosCryptoKey_writeDHPub_v5(const SeosCryptoKey_v5* key,
                            mbedtls_dhm_context* dh);
seos_err_t
SeosCryptoKey_writeDHPrv_v5(const SeosCryptoKey_v5* key,
                            mbedtls_dhm_context* dh);

/**
 * @brief Writes key data into mbedTLS ECDH object
 */
seos_err_t
SeosCryptoKey_writeSECP256r1Pub_v5(const SeosCryptoKey_v5*    key,
                                   mbedtls_ecdh_context* ecdh);
seos_err_t
SeosCryptoKey_writeSECP256r1Prv_v5(const SeosCryptoKey_v5*    key,
                                   mbedtls_ecdh_context* ecdh);

/**
 * @brief Translates key data into RSA public key
 */
INLINE SeosCryptoKey_RSAPub*
SeosCryptoKey_getRSAPub_v5(const SeosCryptoKey_v5* key)
{
    return (SeosCryptoKey_RSAPub*) key->data;
}

/**
 * @brief Translates key data into RSA private key
 */
INLINE SeosCryptoKey_RSAPrv*
SeosCryptoKey_getRSAPrv_v5(const SeosCryptoKey_v5* key)
{
    return (SeosCryptoKey_RSAPrv*) key->data;
}

/**
 * @brief Translates key data into SECP256r1 public key
 */
INLINE SeosCryptoKey_SECP256r1Pub*
SeosCryptoKey_getSECP256r1Pub_v5(const SeosCryptoKey_v5* key)
{
    return (SeosCryptoKey_SECP256r1Pub*) key->data;
}

/**
 * @brief Translates key data into SECP256r1 private key
  */
INLINE SeosCryptoKey_SECP256r1Prv*
SeosCryptoKey_getSECP256r1Prv_v5(const SeosCryptoKey_v5* key)
{
    return (SeosCryptoKey_SECP256r1Prv*) key->data;
}

/**
 * @brief Translates key data into DH public key
 */
INLINE SeosCryptoKey_DHPub*
SeosCryptoKey_getDHPub_v5(const SeosCryptoKey_v5* key)
{
    return (SeosCryptoKey_DHPub*) key->data;
}

/**
 * @brief Translates key data into DH private key
 */
INLINE SeosCryptoKey_DHPrv*
SeosCryptoKey_getDHPrv_v5(const SeosCryptoKey_v5* key)
{
    return (SeosCryptoKey_DHPrv*) key->data;
}

/**
 * @brief Translates key data into AES key
 */
INLINE SeosCryptoKey_AES*
SeosCryptoKey_getAES_v5(const SeosCryptoKey_v5* key)
{
    return (SeosCryptoKey_AES*) key->data;
}

///@}
