/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

#include "Crypto_Impl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLibClient CryptoLibClient_t;

// ------------------------------- Init/Free -----------------------------------

OS_Error_t
CryptoLibClient_init(
    Crypto_Impl_t*            impl,
    const OS_Crypto_Memory_t* memory,
    const if_OS_Crypto_t*     rpc);

OS_Error_t
CryptoLibClient_free(
    CryptoLibClient_t* self);