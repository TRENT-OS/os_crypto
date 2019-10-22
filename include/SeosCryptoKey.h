/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoKey.h
 *
 * @brief Key functions
 *
 */

#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoKey_Impl.h"

#include "seos_err.h"
#include "compiler.h"

#include <stddef.h>

seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*               self,
                       const SeosCrypto_MemIf*      memIf,
                       SeosCryptoRng*               rng,
                       const SeosCryptoKey_Spec*    spec);

seos_err_t
SeosCryptoKey_makePublic(SeosCryptoKey*                 self,
                         const SeosCrypto_MemIf*        memIf,
                         const SeosCryptoKey*           prvKey,
                         const SeosCryptoKey_Attribs*   attribs);

seos_err_t
SeosCryptoKey_import(SeosCryptoKey*             self,
                     const SeosCrypto_MemIf*    memIf,
                     const SeosCryptoKey*       wrapKey,
                     const SeosCryptoKey_Data*  keyData);

seos_err_t
SeosCryptoKey_export(SeosCryptoKey*         self,
                     const SeosCryptoKey*   wrapKey,
                     SeosCryptoKey_Data*    keyData);

seos_err_t
SeosCryptoKey_getParams(SeosCryptoKey*  self,
                        void*           keyParams,
                        size_t*         paramSize);

seos_err_t
SeosCryptoKey_loadParams(const SeosCryptoKey_Param  name,
                         void*                      keyParams,
                         size_t*                    paramSize);

seos_err_t
SeosCryptoKey_free(SeosCryptoKey*           self,
                   const SeosCrypto_MemIf*  memIf);

/**
 * @brief Writes key data into mbedTLS RSA object
 */
seos_err_t
SeosCryptoKey_writeRSAPub(const SeosCryptoKey* key,
                          mbedtls_rsa_context* rsa);
seos_err_t
SeosCryptoKey_writeRSAPrv(const SeosCryptoKey* key,
                          mbedtls_rsa_context* rsa);

/**
 * @brief Writes key data into mbedTLS DH object
 */
seos_err_t
SeosCryptoKey_writeDHPub(const SeosCryptoKey* key,
                         mbedtls_dhm_context* dh);
seos_err_t
SeosCryptoKey_writeDHPrv(const SeosCryptoKey* key,
                         mbedtls_dhm_context* dh);

/**
 * @brief Writes key data into mbedTLS ECDH object
 */
seos_err_t
SeosCryptoKey_writeSECP256r1Pub(const SeosCryptoKey*    key,
                                mbedtls_ecdh_context* ecdh);
seos_err_t
SeosCryptoKey_writeSECP256r1Prv(const SeosCryptoKey*    key,
                                mbedtls_ecdh_context* ecdh);

/**
 * @brief Translates key data into RSA public/private key
 */
INLINE SeosCryptoKey_RSAPub*
SeosCryptoKey_getRSAPub(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_RSAPub*) key->data;
}
INLINE SeosCryptoKey_RSAPrv*
SeosCryptoKey_getRSAPrv(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_RSAPrv*) key->data;
}

/**
 * @brief Translates key data into SECP256r1 public/private key
 */
INLINE SeosCryptoKey_SECP256r1Pub*
SeosCryptoKey_getSECP256r1Pub(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_SECP256r1Pub*) key->data;
}
INLINE SeosCryptoKey_SECP256r1Prv*
SeosCryptoKey_getSECP256r1Prv(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_SECP256r1Prv*) key->data;
}

/**
 * @brief Translates key data into DH public/private key
 */
INLINE SeosCryptoKey_DHPub*
SeosCryptoKey_getDHPub(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_DHPub*) key->data;
}
INLINE SeosCryptoKey_DHPrv*
SeosCryptoKey_getDHPrv(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_DHPrv*) key->data;
}

/**
 * @brief Translates key data into AES key
 */
INLINE SeosCryptoKey_AES*
SeosCryptoKey_getAES(const SeosCryptoKey* key)
{
    return (SeosCryptoKey_AES*) key->data;
}

///@}
