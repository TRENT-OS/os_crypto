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

// Internal types/defines/enums ------------------------------------------------

typedef struct
{
    /**
     * The client's address of the dataport shared with the server
     */
    void* dataPort;
}
SeosCryptoRpc_Client;

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoRpc_Client_init(
    SeosCryptoRpc_Client*                 self,
    const SeosCryptoVtable**              vtable,
    const SeosCryptoApi_RpcClient_Config* cfg);

seos_err_t
SeosCryptoRpc_Client_free(
    SeosCryptoRpc_Client* self);

/** @} */