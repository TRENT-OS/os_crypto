/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file CryptoLibKey.h
 *
 * @brief Crypto library implementation of Key functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/CryptoLibRng.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibKey CryptoLibKey_t;

// Exported functions ----------------------------------------------------------

seos_err_t
CryptoLibKey_generate(
    CryptoLibKey_t**           self,
    const OS_CryptoKey_Spec_t* spec,
    const OS_Crypto_Memory_t*  memIf,
    CryptoLibRng_t*            rng);

seos_err_t
CryptoLibKey_makePublic(
    CryptoLibKey_t**             self,
    const CryptoLibKey_t*        prvKey,
    const OS_CryptoKey_Attrib_t* attribs,
    const OS_Crypto_Memory_t*    memIf);

seos_err_t
CryptoLibKey_import(
    CryptoLibKey_t**           self,
    const OS_CryptoKey_Data_t* keyData,
    const OS_Crypto_Memory_t*  memIf);

seos_err_t
CryptoLibKey_free(
    CryptoLibKey_t*           self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
CryptoLibKey_export(
    const CryptoLibKey_t* self,
    OS_CryptoKey_Data_t*  keyData);

seos_err_t
CryptoLibKey_getParams(
    const CryptoLibKey_t* self,
    void*                 keyParams,
    size_t*               paramSize);

seos_err_t
CryptoLibKey_getAttribs(
    const CryptoLibKey_t*  self,
    OS_CryptoKey_Attrib_t* attribs);

seos_err_t
CryptoLibKey_loadParams(
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize);

// Conversion functions --------------------------------------------------------

seos_err_t
CryptoLibKey_writeRsaPub(
    const CryptoLibKey_t* key,
    mbedtls_rsa_context*  rsa);

seos_err_t
CryptoLibKey_writeRsaPrv(
    const CryptoLibKey_t* key,
    mbedtls_rsa_context*  rsa);

seos_err_t
CryptoLibKey_writeDhPub(
    const CryptoLibKey_t* key,
    mbedtls_dhm_context*  dh);

seos_err_t
CryptoLibKey_writeDhPrv(
    const CryptoLibKey_t* key,
    mbedtls_dhm_context*  dh);

seos_err_t
CryptoLibKey_writeSecp256r1Pub(
    const CryptoLibKey_t* key,
    mbedtls_ecdh_context* ecdh);

seos_err_t
CryptoLibKey_writeSecp256r1Prv(
    const CryptoLibKey_t* key,
    mbedtls_ecdh_context* ecdh);

OS_CryptoKey_Type_t
CryptoLibKey_getType(
    const CryptoLibKey_t* key);

OS_CryptoKey_RsaRub_t*
CryptoLibKey_getRsaPub(
    const CryptoLibKey_t* key);

OS_CryptoKey_RsaRrv_t*
CryptoLibKey_getRsaPrv(
    const CryptoLibKey_t* key);

OS_CryptoKey_Secp256r1Pub_t*
CryptoLibKey_getSecp256r1Pub(
    const CryptoLibKey_t* key);

OS_CryptoKey_Secp256r1Prv_t*
CryptoLibKey_getSecp256r1Prv(
    const CryptoLibKey_t* key);

OS_CryptoKey_DhPub_t*
CryptoLibKey_getDhPub(
    const CryptoLibKey_t* key);

OS_CryptoKey_DhPrv_t*
CryptoLibKey_getDhPrv(
    const CryptoLibKey_t* key);

OS_CryptoKey_Aes_t*
CryptoLibKey_getAes(
    const CryptoLibKey_t* key);

///@}
