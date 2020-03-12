/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib_Key.h
 *
 * @brief Crypto library implementation of Key functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "lib/SeosCryptoLib_Rng.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct SeosCryptoLib_Key SeosCryptoLib_Key;

// Exported functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_Key_generate(
    SeosCryptoLib_Key**           self,
    const SeosCryptoApi_MemIf*    memIf,
    SeosCryptoLib_Rng*            rng,
    const SeosCryptoApi_Key_Spec* spec);

seos_err_t
SeosCryptoLib_Key_makePublic(
    SeosCryptoLib_Key**              self,
    const SeosCryptoApi_MemIf*       memIf,
    const SeosCryptoLib_Key*         prvKey,
    const SeosCryptoApi_Key_Attribs* attribs);

seos_err_t
SeosCryptoLib_Key_import(
    SeosCryptoLib_Key**           self,
    const SeosCryptoApi_MemIf*    memIf,
    const SeosCryptoApi_Key_Data* keyData);

seos_err_t
SeosCryptoLib_Key_free(
    SeosCryptoLib_Key*         self,
    const SeosCryptoApi_MemIf* memIf);

seos_err_t
SeosCryptoLib_Key_export(
    const SeosCryptoLib_Key* self,
    SeosCryptoApi_Key_Data*  keyData);

seos_err_t
SeosCryptoLib_Key_getParams(
    const SeosCryptoLib_Key* self,
    void*                    keyParams,
    size_t*                  paramSize);

seos_err_t
SeosCryptoLib_Key_getAttribs(
    const SeosCryptoLib_Key*   self,
    SeosCryptoApi_Key_Attribs* attribs);

seos_err_t
SeosCryptoLib_Key_loadParams(
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize);

// Conversion functions --------------------------------------------------------

seos_err_t
SeosCryptoLib_Key_writeRsaPub(
    const SeosCryptoLib_Key* key,
    mbedtls_rsa_context*     rsa);

seos_err_t
SeosCryptoLib_Key_writeRsaPrv(
    const SeosCryptoLib_Key* key,
    mbedtls_rsa_context*     rsa);

seos_err_t
SeosCryptoLib_Key_writeDhPub(
    const SeosCryptoLib_Key* key,
    mbedtls_dhm_context*     dh);

seos_err_t
SeosCryptoLib_Key_writeDhPrv(
    const SeosCryptoLib_Key* key,
    mbedtls_dhm_context*     dh);

seos_err_t
SeosCryptoLib_Key_writeSecp256r1Pub(
    const SeosCryptoLib_Key* key,
    mbedtls_ecdh_context*    ecdh);

seos_err_t
SeosCryptoLib_Key_writeSecp256r1Prv(
    const SeosCryptoLib_Key* key,
    mbedtls_ecdh_context*    ecdh);

SeosCryptoApi_Key_Type
SeosCryptoLib_Key_getType(
    const SeosCryptoLib_Key* key);

SeosCryptoApi_Key_RsaRub*
SeosCryptoLib_Key_getRsaPub(
    const SeosCryptoLib_Key* key);

SeosCryptoApi_Key_RsaRrv*
SeosCryptoLib_Key_getRsaPrv(
    const SeosCryptoLib_Key* key);

SeosCryptoApi_Key_Secp256r1Pub*
SeosCryptoLib_Key_getSecp256r1Pub(
    const SeosCryptoLib_Key* key);

SeosCryptoApi_Key_Secp256r1Prv*
SeosCryptoLib_Key_getSecp256r1Prv(
    const SeosCryptoLib_Key* key);

SeosCryptoApi_Key_DhPub*
SeosCryptoLib_Key_getDhPub(
    const SeosCryptoLib_Key* key);

SeosCryptoApi_Key_DhPrv*
SeosCryptoLib_Key_getDhPrv(
    const SeosCryptoLib_Key* key);

SeosCryptoApi_Key_Aes*
SeosCryptoLib_Key_getAes(
    const SeosCryptoLib_Key* key);

///@}
