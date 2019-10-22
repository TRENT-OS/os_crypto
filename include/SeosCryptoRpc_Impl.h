/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCryptoRpc_Impl.h
 *
 * @brief RPC server data structures and constants
 *
 */

#pragma once

#include "SeosCryptoCtx.h"
#include "compiler.h"

#include <sys/user.h>

typedef struct
{
    /**
     * crypto context to be used by the RPC object
     */
    SeosCryptoCtx*  seosCryptoApi;
    /**
     * the server's address of the dataport shared with the client
     */
    void*           serverDataport;
}
SeosCryptoRpc;

typedef SeosCryptoRpc* SeosCryptoRpc_Handle;

/** @} */