/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */
#pragma once

#include "OS_Crypto.h"

#include "lib/CryptoLibKey.h"

#include <stddef.h>

// Exported types/defines/enums ------------------------------------------------

typedef struct CryptoLibMac CryptoLibMac_t;

// Exported functions ----------------------------------------------------------

OS_Error_t
CryptoLibMac_init(
    CryptoLibMac_t**          self,
    const CryptoLibKey_t*     key,
    const OS_CryptoMac_Alg_t  algorithm,
    const OS_Crypto_Memory_t* memory);

OS_Error_t
CryptoLibMac_free(
    CryptoLibMac_t*           self,
    const OS_Crypto_Memory_t* memory);

OS_Error_t
CryptoLibMac_process(
    CryptoLibMac_t* self,
    const void*     data,
    const size_t    dataSize);

OS_Error_t
CryptoLibMac_finalize(
    CryptoLibMac_t* self,
    void*           mac,
    size_t*         macSize);