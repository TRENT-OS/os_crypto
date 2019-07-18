/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
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
/**
 * @brief generate random number
 *
 * @param self (optional) pointer to the seos_crypto context
 * @param flags allows selecting a fast random source for bulk data or more
 *  secure source for cryptographically secure random data. Fast random data
 *  generation is usually implemented uses a PRNG seeded by a nonce obtained
 *  from a slow true RNG
 * @param saltBuffer (optional) is used with PRNGs only, it may be ignore if
 *  random data is obtained from a HW source
 * @param saltLen capacity of saltBuffer
 * @param buffer ///TODO: NOT DOCUMENTED in Wiki
 * @param len capacity of buffer
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_UNSUPPORTED requested random source is not supported or
 *  requested length of random data is not supported for this source
 * @retval SEOS_ERROR_ABORTED operation has been aborted, can happen if random
 *  source had an internal error or became unavailable during the operation. It
 *  may also happen if the operation is running for too long
 *
 */
seos_err_t
SeosCryptoApi_getRandomData(SeosCryptoApi*  self,
                            unsigned int    flags,
                            void const*     saltBuffer,
                            size_t          saltLen,
                            void*           buffer,
                            size_t          dataLen);

/** @} */
