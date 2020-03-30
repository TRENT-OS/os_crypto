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

typedef struct OS_CryptoLibKey OS_CryptoLibKey_t;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibKey_generate(
    OS_CryptoLibKey_t**        self,
    const OS_Crypto_Memory_t*  memIf,
    OS_CryptoLibRng_t*         rng,
    const OS_CryptoKey_Spec_t* spec);

seos_err_t
OS_CryptoLibKey_makePublic(
    OS_CryptoLibKey_t**          self,
    const OS_Crypto_Memory_t*    memIf,
    const OS_CryptoLibKey_t*     prvKey,
    const OS_CryptoKey_Attrib_t* attribs);

seos_err_t
OS_CryptoLibKey_import(
    OS_CryptoLibKey_t**        self,
    const OS_Crypto_Memory_t*  memIf,
    const OS_CryptoKey_Data_t* keyData);

seos_err_t
OS_CryptoLibKey_free(
    OS_CryptoLibKey_t*        self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
OS_CryptoLibKey_export(
    const OS_CryptoLibKey_t* self,
    OS_CryptoKey_Data_t*     keyData);

seos_err_t
OS_CryptoLibKey_getParams(
    const OS_CryptoLibKey_t* self,
    void*                    keyParams,
    size_t*                  paramSize);

seos_err_t
OS_CryptoLibKey_getAttribs(
    const OS_CryptoLibKey_t* self,
    OS_CryptoKey_Attrib_t*   attribs);

seos_err_t
OS_CryptoLibKey_loadParams(
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize);

// Conversion functions --------------------------------------------------------

seos_err_t
OS_CryptoLibKey_writeRsaPub(
    const OS_CryptoLibKey_t* key,
    mbedtls_rsa_context*     rsa);

seos_err_t
OS_CryptoLibKey_writeRsaPrv(
    const OS_CryptoLibKey_t* key,
    mbedtls_rsa_context*     rsa);

seos_err_t
OS_CryptoLibKey_writeDhPub(
    const OS_CryptoLibKey_t* key,
    mbedtls_dhm_context*     dh);

seos_err_t
OS_CryptoLibKey_writeDhPrv(
    const OS_CryptoLibKey_t* key,
    mbedtls_dhm_context*     dh);

seos_err_t
OS_CryptoLibKey_writeSecp256r1Pub(
    const OS_CryptoLibKey_t* key,
    mbedtls_ecdh_context*    ecdh);

seos_err_t
OS_CryptoLibKey_writeSecp256r1Prv(
    const OS_CryptoLibKey_t* key,
    mbedtls_ecdh_context*    ecdh);

OS_CryptoKey_Type_t
OS_CryptoLibKey_getType(
    const OS_CryptoLibKey_t* key);

OS_CryptoKey_RsaRub_t*
OS_CryptoLibKey_getRsaPub(
    const OS_CryptoLibKey_t* key);

OS_CryptoKey_RsaRrv_t*
OS_CryptoLibKey_getRsaPrv(
    const OS_CryptoLibKey_t* key);

OS_CryptoKey_Secp256r1Pub_t*
OS_CryptoLibKey_getSecp256r1Pub(
    const OS_CryptoLibKey_t* key);

OS_CryptoKey_Secp256r1Prv_t*
OS_CryptoLibKey_getSecp256r1Prv(
    const OS_CryptoLibKey_t* key);

OS_CryptoKey_DhPub_t*
OS_CryptoLibKey_getDhPub(
    const OS_CryptoLibKey_t* key);

OS_CryptoKey_DhPrv_t*
OS_CryptoLibKey_getDhPrv(
    const OS_CryptoLibKey_t* key);

OS_CryptoKey_Aes_t*
OS_CryptoLibKey_getAes(
    const OS_CryptoLibKey_t* key);

///@}
