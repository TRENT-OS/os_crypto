/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLib CryptoLib_t;

// ------------------------------- Init/Free -----------------------------------

OS_Error_t
CryptoLib_init(
    Crypto_Impl_t*             impl,
    const OS_Crypto_Memory_t*  memory,
    const if_OS_Entropy_t*     entropy);

OS_Error_t
CryptoLib_free(
    CryptoLib_t* self);