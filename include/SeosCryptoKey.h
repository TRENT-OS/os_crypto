/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoKey.h
 *
 * @brief Key functions and context
 *
 */
#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoKey_Impl.h"

#include "seos_err.h"
#include "compiler.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/dhm.h"

#include <stddef.h>

/**
 * @brief Initializes a SeosCryptoKey context
 *
 */
seos_err_t
SeosCryptoKey_init(SeosCryptoKey*               self,
                   const SeosCrypto_MemIf*      memIf,
                   const SeosCryptoKey_Type     type,
                   const SeosCryptoKey_Flags    flags,
                   const size_t                 bits);

/**
 * @brief Fills a key context with randomly generated data
 *
 */
seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*           self,
                       SeosCryptoRng*           rng);

/**
 * @brief Fills two key contexts with randomly generated data
 *
 */
seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*       prvKey,
                           SeosCryptoKey*       pubKey,
                           SeosCryptoRng*       rng);

/**
 * @brief Imports key data into key context
 *
 */
seos_err_t
SeosCryptoKey_import(SeosCryptoKey*         self,
                     const SeosCryptoKey*   wrapKey,
                     const void*            keyBytes,
                     size_t                 keySize);

/**
 * @brief Exports key context into buffer
 *
 */
seos_err_t
SeosCryptoKey_export(SeosCryptoKey*         self,
                     const SeosCryptoKey*   wrapKey,
                     void*                  buf,
                     size_t*                bufSize);

/**
 * @brief Finishes a key context
 *
 */
seos_err_t
SeosCryptoKey_free(SeosCryptoKey*           self,
                   const SeosCrypto_MemIf*  memIf);

/**
 * @brief Translates key data into RSA public key
 *
 */
INLINE SeosCryptoKey_RSAPub*
SeosCryptoKey_getRSAPub(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_RSAPub*) key->keyBytes;
}

/**
 * @brief Translates key data into RSA private key
 *
 */
INLINE SeosCryptoKey_RSAPrv*
SeosCryptoKey_getRSAPrv(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_RSAPrv*) key->keyBytes;
}

/**
 * @brief Translates key data into SECP256r1 public key
 *
 */
INLINE SeosCryptoKey_SECP256r1Pub*
SeosCryptoKey_getSECP256r1Pub(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_SECP256r1Pub*) key->keyBytes;
}

/**
 * @brief Translates key data into SECP256r1 private key
 *
 */
INLINE SeosCryptoKey_SECP256r1Prv*
SeosCryptoKey_getSECP256r1Prv(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_SECP256r1Prv*) key->keyBytes;
}

/**
 * @brief Translates key data into DH public key
 *
 */
INLINE SeosCryptoKey_DHPub*
SeosCryptoKey_getDHPub(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_DHPub*) key->keyBytes;
}

/**
 * @brief Translates key data into DH private key
 *
 */
INLINE SeosCryptoKey_DHPrv*
SeosCryptoKey_getDHPrv(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_DHPrv*) key->keyBytes;
}

/**
 * @brief Translates key data into AES key
 *
 */
INLINE SeosCryptoKey_AES*
SeosCryptoKey_getAES(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_AES*) key->keyBytes;
}

/**
 * @brief Translates RSA public key into mbedtls struct
 *
 */
seos_err_t
SeosCryptoKey_writeRSAPub(const SeosCryptoKey*        key,
                          mbedtls_rsa_context*        rsa);

/**
 * @brief Translates RSA private key into mbedtls struct
 *
 */
seos_err_t
SeosCryptoKey_writeRSAPrv(const SeosCryptoKey*        key,
                          mbedtls_rsa_context*        rsa);

/**
 * @brief Translates DH public key into mbedtls struct
 *
 */
seos_err_t
SeosCryptoKey_writeDHPub(const SeosCryptoKey*         key,
                         mbedtls_dhm_context*         dh);

/**
 * @brief Translates DH private key into mbedtls struct
 *
 */
seos_err_t
SeosCryptoKey_writeDHPrv(const SeosCryptoKey*         key,
                         mbedtls_dhm_context*         dh);

/**
 * @brief Translates SECP256r1 public key into mbedtls struct
 *
 */
seos_err_t
SeosCryptoKey_writeSECP256r1Pub(const SeosCryptoKey*  key,
                                mbedtls_ecdh_context* ecdh);

/**
 * @brief Translates SECP256r1 private key into mbedtls struct
 *
 */
seos_err_t
SeosCryptoKey_writeSECP256r1Prv(const SeosCryptoKey*  key,
                                mbedtls_ecdh_context* ecdh);

///@}
