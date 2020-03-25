/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file OS_CryptoRpcClient.h
 *
 * @brief RPC client object and functions to access a SEOS Crypto API instance
 * running as RPC server in another component. If configured to act as RPC client,
 * API calls will transparently be mapped to RPC calls and thus to execute
 * in isolation (e.g., on the RPC server running in its own component).
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "OS_CryptoImpl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct OS_CryptoRpcClient OS_CryptoRpcClient;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
OS_CryptoRpcClient_init(
    OS_CryptoImpl*                   impl,
    const OS_Crypto_Memory*          memIf,
    const OS_CryptoRpcClient_Config* cfg);

seos_err_t
OS_CryptoRpcClient_free(
    OS_CryptoRpcClient* self);

/** @} */