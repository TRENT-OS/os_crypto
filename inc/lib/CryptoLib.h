/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

#include "Crypto_Impl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLib CryptoLib_t;

// ------------------------------- Init/Free -----------------------------------

OS_Error_t
CryptoLib_init(
    Crypto_Impl_t*            impl,
    const OS_Crypto_Memory_t* memory,
    const CryptoLib_Config_t* cfg);

OS_Error_t
CryptoLib_free(
    CryptoLib_t* self);