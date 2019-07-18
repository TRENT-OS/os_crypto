/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoAPI.c
 *
 * @brief SEOS Crypto API library
 *
 */
#include "SeosCryptoApi.h"
#include "SeosCrypto.h"
#include "SeosCryptoRpc.h"


// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoApi_initAsLocal(SeosCryptoApi* self, SeosCrypto* crypto)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (crypto == NULL)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        self->isLocalConnection         = true;
        self->connector.local.crypto    = crypto;
    }
    return retval;
}

seos_err_t
SeosCryptoApi_initAsRpc(SeosCryptoApi* self, SeosCryptoClient* client)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (client == NULL)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        self->isLocalConnection    = false;
        self->connector.rpc.client = client;
    }
    return retval;
}

void
SeosCryptoApi_deInit(SeosCryptoApi* self)
{
    return;
}


/***************************** Crypto functions *******************************/
seos_err_t
SeosCryptoApi_getRandomData(SeosCryptoApi* self,
                            unsigned int flags,
                            void const* saltBuffer,
                            size_t saltLen,
                            void* buffer,
                            size_t dataLen)
{
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosCrypto_getRandomData(self->connector.local.crypto,
                                          flags,
                                          saltBuffer,
                                          saltLen,
                                          buffer,
                                          dataLen);
    }
    else
    {
        void* randomDataPtr = NULL;
        retval = SeosCryptoClient_getRandomData(self->connector.rpc.client,
                                                flags,
                                                saltBuffer,
                                                saltLen,
                                                &randomDataPtr,
                                                dataLen);
        memcpy(buffer, randomDataPtr, dataLen);
    }
    return retval;
}
