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
SeosCryptoKey_generate(SeosCryptoKey*           self);

seos_err_t
SeosCryptoKey_generatePair(SeosCryptoKey*       prvKey,
                           SeosCryptoKey*       pubKey);

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

void
SeosCryptoKey_deInit(SeosCrypto_MemIf*          memIf,
                     SeosCryptoKey*             self);

INLINE SeosCryptoKey_RSA_PUBLIC*
SeosCryptoKey_getRsaPublic(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_RSA_PUBLIC*) key->keyBytes;
}

INLINE SeosCryptoKey_RSA_PRIVATE*
SeosCryptoKey_getRsaPrivate(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_RSA_PRIVATE*) key->keyBytes;
}

INLINE SeosCryptoKey_EC_SECP256R1_PUBLIC*
SeosCryptoKey_getEcSecp256r1Public(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_EC_SECP256R1_PUBLIC*) key->keyBytes;
}

INLINE SeosCryptoKey_EC_SECP256R1_PRIVATE*
SeosCryptoKey_getEcSecp256r1Private(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_EC_SECP256R1_PRIVATE*) key->keyBytes;
}

INLINE SeosCryptoKey_DH_PUBLIC*
SeosCryptoKey_getDhPublic(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_DH_PUBLIC*) key->keyBytes;
}

INLINE SeosCryptoKey_DH_PRIVATE*
SeosCryptoKey_getDhPrivate(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_DH_PRIVATE*) key->keyBytes;
}

INLINE SeosCryptoKey_AES*
SeosCryptoKey_getAES(const SeosCryptoKey* key)
{
    return key->empty ? NULL : (SeosCryptoKey_AES*) key->keyBytes;
}

///@}
