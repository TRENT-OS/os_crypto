/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#include "SeosCryptoClient.h"
#include "LibDebug/Debug.h"

#include <string.h>

static const SeosCryptoApi_Vtable SeosCryptoClient_vtable =
{
    .getRandomData  = SeosCryptoClient_getRandomData2,
    .digestInit     = SeosCryptoClient_digestInit,
    .digestClose    = SeosCryptoClient_digestClose,
    .digestUpdate   = SeosCryptoClient_digestUpdate,
    .digestFinalize = SeosCryptoClient_digestFinalize,
    .keyGenerate    = SeosCryptoClient_keyGenerate,
    .keyImport      = SeosCryptoClient_keyImport,
    .keyClose       = SeosCryptoClient_keyClose,
    .cipherInit     = SeosCryptoClient_cipherInit,
    .cipherClose    = SeosCryptoClient_cipherClose,
    .cipherUpdate   = SeosCryptoClient_cipherUpdate,
    .deInit         = SeosCryptoClient_deInit
};

seos_err_t
SeosCryptoClient_init(SeosCryptoClient* self,
                      SeosCryptoRpc_Handle rpcHandle,
                      void* dataport)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    memset(self, 0, sizeof(*self));

    if (NULL == rpcHandle || NULL == dataport)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    self->clientDataport = dataport;
    self->rpcHandle      = rpcHandle;
    self->parent.vtable  = &SeosCryptoClient_vtable;

    retval = SEOS_SUCCESS;
exit:
    return retval;
}

void
SeosCryptoClient_deInit(SeosCryptoApi* api)
{
    return;
}

seos_err_t
SeosCryptoClient_getRandomData(SeosCryptoClient*    self,
                               unsigned int         flags,
                               void const*          saltBuffer,
                               size_t               saltLen,
                               void**               buffer,
                               size_t               dataLen)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == buffer || dataLen > PAGE_SIZE || saltLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (saltBuffer != NULL)
        {
            memcpy(self->clientDataport, saltBuffer, saltLen);
        }
        else
        {
            saltLen = 0;
        }
        retval = SeosCryptoRpc_getRandomData(self->rpcHandle,
                                             flags,
                                             saltLen,
                                             dataLen);
        // we return the place of the answer in our address space
        *buffer = self->clientDataport;
    }
    return retval;
}

seos_err_t
SeosCryptoClient_getRandomData2(SeosCryptoApi*   api,
                                unsigned int     flags,
                                void const*      saltBuffer,
                                size_t           saltLen,
                                void*            buffer,
                                size_t           dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;

    seos_err_t retval   = SEOS_SUCCESS;
    void* data          = NULL;

    retval = SeosCryptoClient_getRandomData(self,
                                            flags,
                                            saltBuffer,
                                            saltLen,
                                            &data,
                                            dataLen);
    if (SEOS_SUCCESS == retval)
    {
        memcpy(buffer, data, dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestInit(SeosCryptoApi*              api,
                            SeosCryptoApi_DigestHandle*    pDigestHandle,
                            SeosCryptoDigest_Algorithm  algorithm,
                            void*                       iv,
                            size_t                      ivLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (ivLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (iv != NULL)
        {
            memcpy(self->clientDataport, iv, ivLen);
        }
        retval = SeosCryptoRpc_digestInit(self->rpcHandle,
                                          pDigestHandle,
                                          algorithm,
                                          ivLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestClose(SeosCryptoApi*             api,
                             SeosCryptoApi_DigestHandle    digestHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    return SeosCryptoRpc_digestClose(self->rpcHandle, digestHandle);
}

seos_err_t
SeosCryptoClient_digestUpdate(SeosCryptoApi*            api,
                              SeosCryptoApi_DigestHandle   digestHandle,
                              const void*               data,
                              size_t                    dataLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data || dataLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, data, dataLen);
        retval = SeosCryptoRpc_digestUpdate(self->rpcHandle,
                                            digestHandle,
                                            dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoApi*          api,
                                SeosCryptoApi_DigestHandle digestHandle,
                                const void*             data,
                                size_t                  dataLen,
                                void**                  digest,
                                size_t*                 digestSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (dataLen > PAGE_SIZE || NULL == digest || NULL == digestSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (data != NULL)
        {
            memcpy(self->clientDataport, data, dataLen);
        }
        retval = SeosCryptoRpc_digestFinalize(self->rpcHandle,
                                              digestHandle,
                                              dataLen);

        if (SEOS_SUCCESS == retval)
        {
            size_t* serverDigestLen = (size_t*) self->clientDataport;
            char*   serverDigest    = &(((char*) self->clientDataport)
                                        [sizeof(*serverDigestLen)]);

            if (*digest != NULL)
            {
                if (*digestSize < *serverDigestLen)
                {
                    retval = SEOS_ERROR_BUFFER_TOO_SMALL;
                }
                else
                {
                    *digestSize = *serverDigestLen;
                    memcpy(*digest, serverDigest, *serverDigestLen);
                    retval = SEOS_SUCCESS;
                }
            }
            else
            {
                *digestSize = *serverDigestLen;
                *digest     = serverDigest;
                retval      = SEOS_SUCCESS;
            }
        }
    }
    return retval;
}

seos_err_t
SeosCryptoClient_keyGenerate(SeosCryptoApi*             api,
                             SeosCryptoApi_KeyHandle*    pKeyHandle,
                             unsigned int             algorithm,
                             unsigned int             flags,
                             size_t                   lenBits)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    return SeosCryptoRpc_keyGenerate(self->rpcHandle,
                                     pKeyHandle,
                                     algorithm,
                                     flags,
                                     lenBits);
}

seos_err_t
SeosCryptoClient_keyImport(SeosCryptoApi*         api,
                           SeosCryptoApi_KeyHandle*  pKeyHandle,
                           unsigned int           algorithm,
                           unsigned int           flags,
                           void const*            keyImportBuffer,
                           size_t                 keyImportLenBits)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval   = SEOS_ERROR_GENERIC;
    size_t sizeRawKey   = keyImportLenBits / CHAR_BIT
                          + ((keyImportLenBits % CHAR_BIT) ? 1 : 0);

    if (sizeRawKey > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, keyImportBuffer, sizeRawKey);
        retval = SeosCryptoRpc_keyImport(self->rpcHandle,
                                         pKeyHandle,
                                         algorithm,
                                         flags,
                                         keyImportLenBits);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_keyClose(SeosCryptoApi*        api,
                          SeosCryptoApi_KeyHandle  keyHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    return SeosCryptoRpc_keyClose(self->rpcHandle, keyHandle);
}

seos_err_t
SeosCryptoClient_cipherInit(SeosCryptoApi*              api,
                            SeosCryptoApi_CipherHandle*    pKeyHandle,
                            SeosCryptoCipher_Algorithm  algorithm,
                            SeosCryptoApi_KeyHandle        key,
                            void*                       iv,
                            size_t                      ivLen)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (ivLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        if (iv != NULL)
        {
            memcpy(self->clientDataport, iv, ivLen);
        }
        retval = SeosCryptoRpc_cipherInit(self->rpcHandle,
                                          pKeyHandle,
                                          algorithm,
                                          key,
                                          ivLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_cipherClose(SeosCryptoApi*             api,
                             SeosCryptoApi_CipherHandle    cipherHandle)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    return SeosCryptoRpc_cipherClose(self->rpcHandle, cipherHandle);
}

seos_err_t
SeosCryptoClient_cipherUpdate(SeosCryptoApi*            api,
                              SeosCryptoApi_CipherHandle   cipherHandle,
                              const void*               data,
                              size_t                    dataLen,
                              void**                    output,
                              size_t*                   outputSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data || dataLen > PAGE_SIZE
        || NULL == output || NULL == outputSize)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, data, dataLen);
        retval = SeosCryptoRpc_cipherUpdate(self->rpcHandle,
                                            cipherHandle,
                                            dataLen);

        if (SEOS_SUCCESS == retval)
        {
            size_t* obtainedOutputSize  = (size_t*) self->clientDataport;
            char*   obtainedOutput      = &(((char*) self->clientDataport)
                                            [sizeof(*outputSize)]);

            if (*output != NULL)
            {
                if (*outputSize < *obtainedOutputSize)
                {
                    retval = SEOS_ERROR_BUFFER_TOO_SMALL;
                }
                else
                {
                    *outputSize = *obtainedOutputSize;
                    memcpy(*output, obtainedOutput, *outputSize);
                    retval = SEOS_SUCCESS;
                }
            }
            else
            {
                *outputSize = *obtainedOutputSize;
                *output     = obtainedOutput;
                retval      = SEOS_SUCCESS;
            }
        }
    }
    return retval;
}

seos_err_t
SeosCryptoClient_cipherFinalize(SeosCryptoApi*          api,
                                SeosCryptoApi_CipherHandle cipherHandle,
                                const void*             data,
                                size_t                  dataLen,
                                void**                  digest,
                                size_t*                 digestSize)
{
    SeosCryptoClient* self = (SeosCryptoClient*) api;
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    /// TBD
    return retval;
}
