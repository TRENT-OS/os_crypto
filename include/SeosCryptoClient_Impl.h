/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoClient_Impl.h
 *
 * @brief RPC client data structures and constants
 *
 */

#pragma once

#include "SeosCryptoRpc_Impl.h"
#include "SeosCryptoCtx.h"

#define SeosCryptoClient_TO_SEOS_CRYPTO_CTX(self) (&(self)->parent)

typedef struct
{
    SeosCryptoCtx           parent;
    /**
     * pointer to be used in the rpc call, this pointer is not valid in our address
     * tell the server which is the correct object in his address space
     * */
    SeosCryptoRpc_Handle    rpcHandle;
    /**
     * the client's address of the dataport shared with the server
     */
    void*                   clientDataport;
}
SeosCryptoClient;

/** @} */
