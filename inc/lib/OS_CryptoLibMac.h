/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLibMac.h
 *
 * @brief Crypto library implementation of Message Authentication Code (MAC) functions
 *
 */

#pragma once

#include "OS_Crypto.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct OS_CryptoLibMac OS_CryptoLibMac_t;

// Exported functions ----------------------------------------------------------

seos_err_t
OS_CryptoLibMac_init(
    OS_CryptoLibMac_t**       self,
    const OS_Crypto_Memory_t* memIf,
    const OS_CryptoMac_Alg_t  algorithm);

seos_err_t
OS_CryptoLibMac_free(
    OS_CryptoLibMac_t*        self,
    const OS_Crypto_Memory_t* memIf);

seos_err_t
OS_CryptoLibMac_start(
    OS_CryptoLibMac_t* self,
    const void*        secret,
    const size_t       secretSize);

seos_err_t
OS_CryptoLibMac_process(
    OS_CryptoLibMac_t* self,
    const void*        data,
    const size_t       dataSize);

seos_err_t
OS_CryptoLibMac_finalize(
    OS_CryptoLibMac_t* self,
    void*              mac,
    size_t*            macSize);

/** @} */
