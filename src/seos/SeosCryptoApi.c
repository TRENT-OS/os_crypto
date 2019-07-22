/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
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
    Debug_ASSERT_SELF(self);
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
        retval = SeosCryptoClient_getRandomData2(self->connector.rpc.client,
                                                 flags,
                                                 saltBuffer,
                                                 saltLen,
                                                 buffer,
                                                 dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoApi_digestInit(SeosCryptoApi*              self,
                         SeosCrypto_DigestHandle*    pDigestHandle,
                         SeosCryptoDigest_Algorithm  algorithm,
                         char*                       iv,
                         size_t                      ivLen)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosCrypto_digestInit(self->connector.local.crypto,
                                       pDigestHandle,
                                       algorithm,
                                       iv,
                                       ivLen);
    }
    else
    {
        retval = SeosCryptoClient_digestInit(self->connector.rpc.client,
                                             pDigestHandle,
                                             algorithm,
                                             iv,
                                             ivLen);
    }
    return retval;
}

void
SeosCryptoApi_digestClose(SeosCryptoApi*             self,
                          SeosCrypto_DigestHandle    digestHandle)
{
    Debug_ASSERT_SELF(self);

    if (self->isLocalConnection)
    {
        SeosCrypto_digestClose(self->connector.local.crypto, digestHandle);
    }
    else
    {
        SeosCryptoClient_digestClose(self->connector.rpc.client, digestHandle);
    }
}

seos_err_t
SeosCryptoApi_digestUpdate(SeosCryptoApi*            self,
                           SeosCrypto_DigestHandle   digestHandle,
                           const void*               data,
                           size_t                    dataLen)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosCrypto_digestUpdate(self->connector.local.crypto,
                                         digestHandle,
                                         data,
                                         dataLen);
    }
    else
    {
        retval = SeosCryptoClient_digestUpdate(self->connector.rpc.client,
                                               digestHandle,
                                               data,
                                               dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoApi_digestFinalize(SeosCryptoApi*              self,
                             SeosCrypto_DigestHandle     digestHandle,
                             const void*                 data,
                             size_t                      dataLen,
                             void*                       digest,
                             size_t                      digestSize)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosCrypto_digestFinalize(self->connector.local.crypto,
                                           digestHandle,
                                           data,
                                           dataLen,
                                           digest,
                                           digestSize);
    }
    else
    {
        retval = SeosCryptoClient_digestFinalize2(self->connector.rpc.client,
                                                  digestHandle,
                                                  data,
                                                  dataLen,
                                                  digest,
                                                  digestSize);
    }
    return retval;
}

seos_err_t
SeosCryptoApi_keyGenerate(SeosCryptoApi*           self,
                          SeosCrypto_KeyHandle*    pKeyHandle,
                          unsigned int             algorithm,
                          unsigned int             flags,
                          size_t                   lenBits)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosCrypto_keyGenerate(self->connector.local.crypto,
                                        pKeyHandle,
                                        algorithm,
                                        flags,
                                        lenBits);
    }
    else
    {
        retval = SeosCryptoClient_keyGenerate(self->connector.rpc.client,
                                              pKeyHandle,
                                              algorithm,
                                              flags,
                                              lenBits);
    }
    return retval;
}
seos_err_t
SeosCryptoApi_keyImport(SeosCryptoApi*          self,
                        SeosCrypto_KeyHandle*   pKeyHandle,
                        unsigned int            algorithm,
                        unsigned int            flags,
                        void const*             keyImportBuffer,
                        size_t                  keyImportLenBits)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosCrypto_keyImport(self->connector.local.crypto,
                                      pKeyHandle,
                                      algorithm,
                                      flags,
                                      keyImportBuffer,
                                      keyImportLenBits);
    }
    else
    {
        retval = SeosCryptoClient_keyImport(self->connector.rpc.client,
                                            pKeyHandle,
                                            algorithm,
                                            flags,
                                            keyImportBuffer,
                                            keyImportLenBits);
    }
    return retval;
}
