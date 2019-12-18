/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoRpcClient.h
 *
 * @brief Client object and functions to access the SEOS crypto API running on
 *  a camkes server. May of the functions here are just a wrapper of the
 *  SeosCryptoRpcServer functions running on the server and called by the client via
 *  RPC calls.
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
    const SeosCryptoApi_Vtable**          vtable,
    const SeosCryptoApi_RpcClient_Config* cfg);

seos_err_t
SeosCryptoRpcClient_free(
    SeosCryptoRpcClient* self);

/** @} */