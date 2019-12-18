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

#include "SeosCryptoApi.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"

#include "LibDebug/Debug.h"

#include "compiler.h"

#include <stddef.h>
#include <stdint.h>

// Internal types/defines/enums ------------------------------------------------

/**
 * How often do we want to retry finding a suitable prime P and also
 * a suitable X with 2 <= X <= P-2?
 */
#define SeosCryptoKey_DH_GEN_RETRIES    10

#define SeosCryptoKey_DH_GENERATOR      2       ///< Generator for DH
#define SeosCryptoKey_RSA_EXPONENT      65537   ///< Public exp. 2^16+1

struct SeosCryptoKey
{
    SeosCryptoApi_Key_Type type;
    SeosCryptoApi_Key_Attribs attribs;
    void* data;
    uint32_t size;
};

// Internal functions ----------------------------------------------------------

/**
 * Make sure that these structs are smaller than the width of the dataport so
 * that we do not have any problem when passing them from SeosCryptoRpcClient to
 * SeosCryptoRpcServer via camkes-generated RPC calls.
 *
 * We have to do this here instead in the SeosCryptoKey_Impl.h header, because
 * we need #defines from SeosCryptoLib_Impl.h and including that file in the
 * SeosCryptoKey_Impl.h will lead to a mess.
 */
Debug_STATIC_ASSERT(sizeof(SeosCryptoApi_Key_Spec)
                    <= SeosCryptoApi_SIZE_DATAPORT);
Debug_STATIC_ASSERT(sizeof(SeosCryptoApi_Key_Data)
                    <= SeosCryptoApi_SIZE_DATAPORT);

seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*                self,
                       const SeosCryptoApi_MemIf*    memIf,
                       SeosCryptoRng*                rng,
                       const SeosCryptoApi_Key_Spec* spec);

seos_err_t
SeosCryptoKey_makePublic(SeosCryptoKey*                   self,
                         const SeosCryptoApi_MemIf*       memIf,
                         const SeosCryptoKey*             prvKey,
                         const SeosCryptoApi_Key_Attribs* attribs);

seos_err_t
SeosCryptoKey_import(SeosCryptoKey*                self,
                     const SeosCryptoApi_MemIf*    memIf,
                     const SeosCryptoKey*          wrapKey,
                     const SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoKey_export(SeosCryptoKey*          self,
                     const SeosCryptoKey*    wrapKey,
                     SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoKey_getParams(SeosCryptoKey* self,
                        void*          keyParams,
                        size_t*        paramSize);

seos_err_t
SeosCryptoKey_loadParams(const SeosCryptoApi_Key_Param name,
                         void*                         keyParams,
                         size_t*                       paramSize);

seos_err_t
SeosCryptoKey_free(SeosCryptoKey*             self,
                   const SeosCryptoApi_MemIf* memIf);

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
SeosCryptoKey_writeSECP256r1Pub(const SeosCryptoKey*  key,
                                mbedtls_ecdh_context* ecdh);
seos_err_t
SeosCryptoKey_writeSECP256r1Prv(const SeosCryptoKey*  key,
                                mbedtls_ecdh_context* ecdh);

/**
 * @brief Translates key data into RSA public/private key
 */
INLINE SeosCryptoApi_Key_RsaRub*
SeosCryptoKey_getRSAPub(const SeosCryptoKey* key)
{
    return (SeosCryptoApi_Key_RsaRub*) key->data;
}
INLINE SeosCryptoApi_Key_RsaRrv*
SeosCryptoKey_getRSAPrv(const SeosCryptoKey* key)
{
    return (SeosCryptoApi_Key_RsaRrv*) key->data;
}

/**
 * @brief Translates key data into SECP256r1 public/private key
 */
INLINE SeosCryptoApi_Key_Secp256r1Pub*
SeosCryptoKey_getSECP256r1Pub(const SeosCryptoKey* key)
{
    return (SeosCryptoApi_Key_Secp256r1Pub*) key->data;
}
INLINE SeosCryptoApi_Key_Secp256r1Prv*
SeosCryptoKey_getSECP256r1Prv(const SeosCryptoKey* key)
{
    return (SeosCryptoApi_Key_Secp256r1Prv*) key->data;
}

/**
 * @brief Translates key data into DH public/private key
 */
INLINE SeosCryptoApi_Key_DhPub*
SeosCryptoKey_getDHPub(const SeosCryptoKey* key)
{
    return (SeosCryptoApi_Key_DhPub*) key->data;
}
INLINE SeosCryptoApi_Key_DhPrv*
SeosCryptoKey_getDHPrv(const SeosCryptoKey* key)
{
    return (SeosCryptoApi_Key_DhPrv*) key->data;
}

/**
 * @brief Translates key data into AES key
 */
INLINE SeosCryptoApi_Key_Aes*
SeosCryptoKey_getAES(const SeosCryptoKey* key)
{
    return (SeosCryptoApi_Key_Aes*) key->data;
}

///@}
