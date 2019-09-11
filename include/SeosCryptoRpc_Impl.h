/* Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoRpc_Impl.h
 *
 * @brief Underlying implementation related definitions of SeosCryptoRpc
 *
 */

#pragma once

#include "SeosCryptoCtx.h"

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