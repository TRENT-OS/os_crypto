/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#include "SeosCryptoClient.h"
#include "LibDebug/Debug.h"

#include <string.h>

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
    retval = SEOS_SUCCESS;
exit:
    return retval;
}

void
SeosCryptoClient_deInit(SeosCryptoClient* self)
{
    // does nothing
}

seos_err_t
SeosCryptoClient_getRandomData(SeosCryptoClient* self,
                               unsigned int flags,
                               void const** buffer,
                               size_t  dataLen)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == buffer || dataLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // we return the place of the answer in our address space
        *buffer = self->clientDataport;
        retval = SeosCryptoRpc_getRandomData(self->rpcHandle,
                                             flags,
                                             dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestInit(SeosCryptoClient* self,
                            SeosCryptoDigest_Algorithm algorithm,
                            char* iv,
                            size_t ivLen)
{
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
        retval = SeosCryptoRpc_digestInit(self->rpcHandle, algorithm, ivLen);
    }
    return retval;
}

void
SeosCryptoClient_digestClose(SeosCryptoClient* self)
{
    Debug_ASSERT_SELF(self);

    SeosCryptoRpc_digestClose(self->rpcHandle);
}

seos_err_t
SeosCryptoClient_digestUpdate(SeosCryptoClient* self,
                              const char* data,
                              size_t dataLen)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == data || dataLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, data, dataLen);
        retval = SeosCryptoRpc_digestUpdate(self->rpcHandle, dataLen);
    }
    return retval;
}

seos_err_t
SeosCryptoClient_digestFinalize(SeosCryptoClient* self,
                                const char* data,
                                size_t dataLen,
                                char** digest,
                                size_t* digestSize)
{
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
        retval = SeosCryptoRpc_digestFinalize(self->rpcHandle, dataLen);

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
SeosCryptoClient_cipherInit(SeosCryptoClient* self,
                            SeosCryptoCipher_Algorithm algorithm,
                            SeosCrypto_KeyHandle key,
                            char* iv,
                            size_t ivLen)
{
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
                                          algorithm,
                                          key,
                                          ivLen);
    }
    return retval;
}

void
SeosCryptoClient_cipherClose(SeosCryptoClient* self)
{
    Debug_ASSERT_SELF(self);

    SeosCryptoRpc_cipherClose(self->rpcHandle);
}

seos_err_t
SeosCryptoClient_cipherUpdate(SeosCryptoClient* self,
                              const char* data,
                              size_t dataLen,
                              char** output,
                              size_t* outputSize)
{
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
        retval = SeosCryptoRpc_cipherUpdate(self->rpcHandle, dataLen);

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
SeosCryptoClient_cipherFinalize(SeosCryptoClient* self,
                                const char* data,
                                size_t dataLen,
                                char** digest,
                                size_t* digestSize)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    /// TBD
    return retval;
}
