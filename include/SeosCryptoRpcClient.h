/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file SeosCryptoRpcClient.h
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
     * Pointer to be used in the RPC call, this pointer is not valid in our address
     * tell the server which is the correct object in his address space
     * */
    SeosCryptoApi* api;
    /**
     * The client's address of the dataport shared with the server
     */
    void* dataPort;
}
SeosCryptoRpcClient;

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoRpcClient_init(
    SeosCryptoRpcClient*                  self,
    const SeosCryptoVtable**              vtable,
    const SeosCryptoApi_RpcClient_Config* cfg);

seos_err_t
SeosCryptoRpcClient_free(
    SeosCryptoRpcClient* self);

/** @} */