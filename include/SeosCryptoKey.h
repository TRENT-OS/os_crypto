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
 * @brief initializes a SeosCryptoKey context
 *
 */
seos_err_t
SeosCryptoKey_init(SeosCrypto_MemIf*            memIf,
                   SeosCryptoKey*               self,
                   unsigned int                 type,
                   SeosCryptoKey_Flag           flags,
                   size_t                       bits);

seos_err_t
SeosCryptoKey_generate(SeosCryptoKey*           self,
                       SeosCryptoRng*           rng);

seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*       prvKey,
                           SeosCryptoKey*       pubKey,
                           SeosCryptoRng*       rng);

seos_err_t
SeosCryptoKey_import(SeosCryptoKey*             self,
                     SeosCryptoKey*             wrapKey,
                     const void*                keyBytes,
                     size_t                     keySize);

seos_err_t
SeosCryptoKey_export(SeosCryptoKey*             self,
                     SeosCryptoKey*             wrapKey,
                     void**                     buf,
                     size_t*                    bufSize);

seos_err_t
SeosCryptoKey_deInit(SeosCrypto_MemIf*          memIf,
                     SeosCryptoKey*             self);

INLINE SeosCryptoKey_RSAPub*
SeosCryptoKey_getRSAPub(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_RSAPub*) key->keyBytes;
}

INLINE SeosCryptoKey_RSAPrv*
SeosCryptoKey_getRSAPrv(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_RSAPrv*) key->keyBytes;
}

INLINE SeosCryptoKey_SECP256r1Pub*
SeosCryptoKey_getSECP256r1Pub(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_SECP256r1Pub*) key->keyBytes;
}

INLINE SeosCryptoKey_SECP256r1Prv*
SeosCryptoKey_getSECP256r1Prv(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_SECP256r1Prv*) key->keyBytes;
}

INLINE SeosCryptoKey_DHPub*
SeosCryptoKey_getDHPub(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_DHPub*) key->keyBytes;
}

INLINE SeosCryptoKey_DHPrv*
SeosCryptoKey_getDHPrv(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_DHPrv*) key->keyBytes;
}

INLINE SeosCryptoKey_AES*
SeosCryptoKey_getAES(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_AES*) key->keyBytes;
}

seos_err_t
SeosCryptoKey_writeRSAPub(const SeosCryptoKey*        key,
                          mbedtls_rsa_context*        rsa);

seos_err_t
SeosCryptoKey_writeRSAPrv(const SeosCryptoKey*        key,
                          mbedtls_rsa_context*        rsa);

seos_err_t
SeosCryptoKey_writeDHPub(const SeosCryptoKey*         key,
                         mbedtls_dhm_context*         dh);

seos_err_t
SeosCryptoKey_writeDHPrv(const SeosCryptoKey*         key,
                         mbedtls_dhm_context*         dh);

seos_err_t
SeosCryptoKey_writeSECP256r1Pub(const SeosCryptoKey*  key,
                                mbedtls_ecdh_context* ecdh);

seos_err_t
SeosCryptoKey_writeSECP256r1Prv(const SeosCryptoKey*  key,
                                mbedtls_ecdh_context* ecdh);

///@}
