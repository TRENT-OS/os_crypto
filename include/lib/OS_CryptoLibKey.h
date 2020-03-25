/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLibKey.h
 *
 * @brief Crypto library implementation of Key functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/OS_CryptoLibRng.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct OS_CryptoLibKey OS_CryptoLibKey;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibKey_generate(
    OS_CryptoLibKey**        self,
    const OS_Crypto_Memory*  memIf,
    OS_CryptoLibRng*         rng,
    const OS_CryptoKey_Spec* spec);

seos_err_t
OS_CryptoLibKey_makePublic(
    OS_CryptoLibKey**           self,
    const OS_Crypto_Memory*     memIf,
    const OS_CryptoLibKey*      prvKey,
    const OS_CryptoKey_Attribs* attribs);

seos_err_t
OS_CryptoLibKey_import(
    OS_CryptoLibKey**        self,
    const OS_Crypto_Memory*  memIf,
    const OS_CryptoKey_Data* keyData);

seos_err_t
OS_CryptoLibKey_free(
    OS_CryptoLibKey*        self,
    const OS_Crypto_Memory* memIf);

seos_err_t
OS_CryptoLibKey_export(
    const OS_CryptoLibKey* self,
    OS_CryptoKey_Data*     keyData);

seos_err_t
OS_CryptoLibKey_getParams(
    const OS_CryptoLibKey* self,
    void*                  keyParams,
    size_t*                paramSize);

seos_err_t
OS_CryptoLibKey_getAttribs(
    const OS_CryptoLibKey* self,
    OS_CryptoKey_Attribs*  attribs);

seos_err_t
OS_CryptoLibKey_loadParams(
    const OS_CryptoKey_Param name,
    void*                    keyParams,
    size_t*                  paramSize);

// Conversion functions --------------------------------------------------------

seos_err_t
OS_CryptoLibKey_writeRsaPub(
    const OS_CryptoLibKey* key,
    mbedtls_rsa_context*   rsa);

seos_err_t
OS_CryptoLibKey_writeRsaPrv(
    const OS_CryptoLibKey* key,
    mbedtls_rsa_context*   rsa);

seos_err_t
OS_CryptoLibKey_writeDhPub(
    const OS_CryptoLibKey* key,
    mbedtls_dhm_context*   dh);

seos_err_t
OS_CryptoLibKey_writeDhPrv(
    const OS_CryptoLibKey* key,
    mbedtls_dhm_context*   dh);

seos_err_t
OS_CryptoLibKey_writeSecp256r1Pub(
    const OS_CryptoLibKey* key,
    mbedtls_ecdh_context*  ecdh);

seos_err_t
OS_CryptoLibKey_writeSecp256r1Prv(
    const OS_CryptoLibKey* key,
    mbedtls_ecdh_context*  ecdh);

OS_CryptoKey_Type
OS_CryptoLibKey_getType(
    const OS_CryptoLibKey* key);

OS_CryptoKey_RsaRub*
OS_CryptoLibKey_getRsaPub(
    const OS_CryptoLibKey* key);

OS_CryptoKey_RsaRrv*
OS_CryptoLibKey_getRsaPrv(
    const OS_CryptoLibKey* key);

OS_CryptoKey_Secp256r1Pub*
OS_CryptoLibKey_getSecp256r1Pub(
    const OS_CryptoLibKey* key);

OS_CryptoKey_Secp256r1Prv*
OS_CryptoLibKey_getSecp256r1Prv(
    const OS_CryptoLibKey* key);

OS_CryptoKey_DhPub*
OS_CryptoLibKey_getDhPub(
    const OS_CryptoLibKey* key);

OS_CryptoKey_DhPrv*
OS_CryptoLibKey_getDhPrv(
    const OS_CryptoLibKey* key);

OS_CryptoKey_Aes*
OS_CryptoLibKey_getAes(
    const OS_CryptoLibKey* key);

///@}
