/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file CryptoLibClient.h
 *
 * @brief RPC client object and functions to access a SEOS Crypto API instance
 * running as RPC server in another component. If configured to act as RPC client,
 * API calls will transparently be mapped to RPC calls and thus to execute
 * in isolation (e.g., on the RPC server running in its own component).
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "Crypto_Impl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLibClient CryptoLibClient_t;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
CryptoLibClient_init(
    Crypto_Impl_t*                  impl,
    const OS_Crypto_Memory_t*       memory,
    const CryptoLibClient_Config_t* cfg);

seos_err_t
CryptoLibClient_free(
    CryptoLibClient_t* self);

/** @} */