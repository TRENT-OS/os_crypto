/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoAPI.h
 *
 * @brief SEOS Crypto API library
 *
 */
#pragma once

#include "SeosCrypto.h"
#include "SeosCryptoClient.h"

typedef struct
{
    SeosCrypto* crypto;
}
SeosCryptoApi_LocalConnector;

typedef struct
{
    SeosCryptoClient* client;
}
SeosCryptoApi_RpcConnector;

typedef struct
{
    union
    {
        SeosCryptoApi_LocalConnector  local;
        SeosCryptoApi_RpcConnector    rpc;
    }
    connector;
    bool isLocalConnection;
}
SeosCryptoApi;

typedef void* SeosCryptoApi_Handle;

seos_err_t
SeosCryptoApi_initAsLocal(SeosCryptoApi* self, SeosCrypto* crypto);

seos_err_t
SeosCryptoApi_initAsRpc(SeosCryptoApi* self, SeosCryptoClient* client);

void
SeosCryptoApi_deInit(SeosCryptoApi* self);


/***************************** Crypto functions *******************************/
seos_err_t
SeosCryptoApi_getRandomData(SeosCryptoApi* self,
                            unsigned int flags,
                            void const* saltBuffer,
                            size_t saltLen,
                            void* buffer,
                            size_t dataLen);

/** @} */
