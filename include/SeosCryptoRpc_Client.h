/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file SeosCryptoRpc_Client.h
 *
 * @brief RPC client object and functions to access a SEOS Crypto API instance
 * running as RPC server in another component. If configured to act as RPC client,
 * API calls will transparently be mapped to RPC calls and thus to execute
 * in isolation (e.g., on the RPC server running in its own component).
 *
 */

#pragma once

#include "SeosCryptoApi.h"

// -------------------------- defines/types/variables --------------------------

typedef struct SeosCryptoRpc_Client SeosCryptoRpc_Client;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
SeosCryptoRpc_Client_init(
    SeosCryptoApi_Impl*               impl,
    const SeosCryptoApi_MemIf*        memIf,
    const SeosCryptoRpcClient_Config* cfg);

seos_err_t
SeosCryptoRpc_Client_free(
    SeosCryptoRpc_Client* self);

/** @} */