/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file CryptoLibMac.h
 *
 * @brief Crypto library implementation of Message Authentication Code (MAC) functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibMac CryptoLibMac_t;

// Exported functions ----------------------------------------------------------

seos_err_t
CryptoLibMac_init(
    CryptoLibMac_t**          self,
    const OS_CryptoMac_Alg_t  algorithm,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
CryptoLibMac_free(
    CryptoLibMac_t*           self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
CryptoLibMac_start(
    CryptoLibMac_t* self,
    const void*     secret,
    const size_t    secretSize);

seos_err_t
CryptoLibMac_process(
    CryptoLibMac_t* self,
    const void*     data,
    const size_t    dataSize);

seos_err_t
CryptoLibMac_finalize(
    CryptoLibMac_t* self,
    void*           mac,
    size_t*         macSize);

/** @} */
