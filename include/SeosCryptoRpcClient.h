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
#include "SeosCryptoCtx.h"

// Internal types/defines/enums ------------------------------------------------

typedef struct
{
    SeosCryptoApi_Context parent;
    /**
     * pointer to be used in the rpc call, this pointer is not valid in our address
     * tell the server which is the correct object in his address space
     * */
    SeosCryptoApi_RpcServer rpcHandle;
    /**
     * the client's address of the dataport shared with the server
     */
    void* clientDataport;
}
SeosCryptoRpcClient;

// Internal functions ----------------------------------------------------------

/**
 * @brief constructor of a seos crypto client
 *
 * @param self (required) pointer to the seos crypto client object to be
 *  constructed
 * @param rpcHandle handle to point the remote RPC context
 * @param dataport pointer to the dataport connected to the server
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 *
 */
seos_err_t
SeosCryptoRpcClient_init(
    SeosCryptoRpcClient*    self,
    SeosCryptoApi_RpcServer rpcHandle,
    void*                   dataport);

seos_err_t
SeosCryptoRpcClient_free(
    SeosCryptoApi_Context* api);

/** @} */