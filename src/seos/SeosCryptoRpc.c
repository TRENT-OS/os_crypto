#include "SeosCryptoRpc.h"
#include "SeosCrypto.h"

#include "LibDebug/Debug.h"

#include <string.h>
#include <stdlib.h>

#define SALT_BUFFER_SIZE 16

///TODO: replace Debug_ASSERT_SELF() with a check of the handle

seos_err_t
SeosCryptoRpc_init(SeosCryptoRpc* self,
                   SeosCrypto* seosCryptoApiCtx,
                   void* serverDataport)
{
    Debug_ASSERT_SELF(self);
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == seosCryptoApiCtx || NULL == serverDataport)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    if (seos_rng_init(&self->rng,
                      SeosCrypto_RANDOM_SEED_STR,
                      sizeof(SeosCrypto_RANDOM_SEED_STR) - 1 ))
    {
        retval = SEOS_ERROR_ABORTED;
        goto exit;
    }
    memset(self, 0, sizeof(*self));
    self->seosCryptoApiCtx  = seosCryptoApiCtx;
    self->serverDataport    = serverDataport;
    retval                  = SEOS_SUCCESS;
exit:
    return retval;
}

void
SeosCryptoRpc_deInit(SeosCryptoRpc* self)
{
    seos_rng_free(&self->rng);
}

seos_err_t
SeosCryptoRpc_getRandomData(SeosCryptoRpc* self,
                            unsigned int flags,
                            size_t dataLen)
{
    Debug_ASSERT_SELF(self);

    char salt_buffer[SALT_BUFFER_SIZE];

    //TODO: validate server_handle
    return dataLen > PAGE_SIZE ?
           SEOS_ERROR_INVALID_PARAMETER :
           SeosCrypto_getRandomData(self->seosCryptoApiCtx,
                                    flags,
                                    salt_buffer,
                                    sizeof(salt_buffer),
                                    self->serverDataport,
                                    dataLen);
}

seos_err_t
SeosCryptoRpc_digestInit(SeosCryptoRpc* self,
                         SeosCryptoDigest_Algorithm algorithm,
                         size_t ivLen)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s: algo %d, ivLen %u",
                    __func__,
                    algorithm,
                    ivLen);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self->seosCryptoApiCtx->mem.memIf.malloc
        || NULL == self->seosCryptoApiCtx->mem.memIf.free)
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else if (self->seosCryptoDigest != NULL)
    {
        retval = SEOS_ERROR_OPERATION_DENIED;
    }
    else
    {
        self->seosCryptoDigest = malloc(sizeof(*self->seosCryptoDigest));
        if (NULL == self->seosCryptoDigest)
        {
            retval = SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        else
        {
            retval = SeosCryptoDigest_init(self->seosCryptoDigest,
                                           algorithm,
                                           self->serverDataport,
                                           ivLen);
        }
    }

    return retval;
}

void
SeosCryptoRpc_digestClose(SeosCryptoRpc* self)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s", __func__);

    if (self->seosCryptoDigest != NULL)
    {
        SeosCryptoDigest_deInit(self->seosCryptoDigest);
        self->seosCryptoApiCtx->mem.memIf.free(self->seosCryptoDigest);
        self->seosCryptoDigest = NULL;
    }
}

seos_err_t
SeosCryptoRpc_digestUpdate(SeosCryptoRpc* self,
                           size_t len)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s", __func__);

    seos_err_t retval = (len > PAGE_SIZE) ?
                        SEOS_ERROR_INVALID_PARAMETER :
                        SeosCryptoDigest_update(self->seosCryptoDigest,
                                                self->serverDataport,
                                                len);
    return retval;
}

seos_err_t
SeosCryptoRpc_digestFinalize(SeosCryptoRpc* self,
                             size_t len)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s", __func__);

    char*   digest  = NULL;
    size_t  size    = 0;

    seos_err_t retval = (len > PAGE_SIZE) ?
                        SEOS_ERROR_INVALID_PARAMETER :
                        SeosCryptoDigest_finalize(self->seosCryptoDigest,
                                                  len ?
                                                  self->serverDataport : NULL,
                                                  len,
                                                  &digest,
                                                  &size);
    if (SEOS_SUCCESS == retval)
    {
        if (NULL == digest)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            void* dest = memcpy(self->serverDataport, &size, sizeof(size))
                         + sizeof(size);
            memcpy(dest, digest, size);
        }
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_cipherInit(SeosCryptoRpc* self,
                         SeosCryptoCipher_Algorithm algorithm,
                         SeosCrypto_KeyHandle keyHandle,
                         size_t ivLen)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s: algo %d, keyHandle %p, ivLen %zu",
                    __func__,
                    algorithm,
                    keyHandle
                    ivLen);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self->seosCryptoApiCtx->mem.memIf.malloc
        || NULL == self->seosCryptoApiCtx->mem.memIf.free)
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else if (self->seosCryptoCipher != NULL)
    {
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    else
    {
        self->seosCryptoCipher = malloc(sizeof(*self->seosCryptoCipher));
        if (NULL == self->seosCryptoCipher)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            if (seos_rng_init(&self->rng,
                              SeosCrypto_RANDOM_SEED_STR,
                              sizeof(SeosCrypto_RANDOM_SEED_STR) - 1 ))
            {
                retval = SEOS_ERROR_ABORTED;
                goto exit;
            }
            retval = SeosCryptoRng_init(&self->seosCryptoRng,
                                        &self->rng,
                                        (SeosCryptoRng_ImplRngFunc)
                                        seos_rng_get_prng_bytes);
            if (retval != SEOS_SUCCESS)
            {
                goto err0;
            }
            retval = SeosCryptoCipher_init(self->seosCryptoCipher,
                                           algorithm,
                                           keyHandle,
                                           &self->seosCryptoRng,
                                           self->serverDataport,
                                           ivLen);
            if (retval != SEOS_SUCCESS)
            {
                goto err1;
            }
        }
    }
    goto exit;
err1:
    SeosCryptoRng_deInit(&self->seosCryptoRng);
err0:
    seos_rng_free(&self->rng);
exit:
    return retval;
}

void
SeosCryptoRpc_cipherClose(SeosCryptoRpc* self)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s", __func__);

    if (self->seosCryptoCipher != NULL)
    {
        SeosCryptoCipher_deInit(self->seosCryptoCipher);
        SeosCryptoRng_deInit(&self->seosCryptoRng);
        self->seosCryptoApiCtx->mem.memIf.free(self->seosCryptoCipher);
        self->seosCryptoCipher = NULL;
    }
}

seos_err_t
SeosCryptoRpc_cipherUpdate(SeosCryptoRpc* self,
                           size_t len)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s", __func__);

    char*   output      = NULL;
    size_t  outputSize  = 0;

    seos_err_t retval = (len > PAGE_SIZE) ?
                        SEOS_ERROR_INVALID_PARAMETER :
                        SeosCryptoCipher_update(self->seosCryptoCipher,
                                                self->serverDataport,
                                                len,
                                                &output,
                                                &outputSize);
    if (SEOS_SUCCESS == retval)
    {
        if (NULL == output)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else if (outputSize + sizeof(outputSize) > PAGE_SIZE)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            void* dest = memcpy(self->serverDataport,
                                &outputSize,
                                sizeof(outputSize)) + sizeof(outputSize);
            memcpy(dest, output, outputSize);
        }
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_cipherFinalize(SeosCryptoRpc* self,
                             size_t len)
{
    Debug_ASSERT_SELF(self);

    Debug_LOG_TRACE("%s", __func__);

    char*   output      = NULL;
    char*   tag         = NULL;
    size_t  outputSize  = 0;
    size_t  tagSize     = 0;

    seos_err_t retval = (len > PAGE_SIZE) ?
                        SEOS_ERROR_INVALID_PARAMETER :
                        SeosCryptoCipher_finalize(self->seosCryptoCipher,
                                                  self->serverDataport,
                                                  len,
                                                  &output,
                                                  &outputSize,
                                                  &tag,
                                                  &tagSize);
    if (SEOS_SUCCESS == retval)
    {
        if (NULL == output || NULL == tag)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else if (outputSize + sizeof(outputSize) * 2 + tagSize > PAGE_SIZE)
        {
            retval = SEOS_ERROR_ABORTED;
        }
        else
        {
            void* dest = memcpy(self->serverDataport,
                                &outputSize,
                                sizeof(outputSize)) + sizeof(outputSize);
            dest = memcpy(dest, output, outputSize) + outputSize;
            dest = memcpy(dest, &tagSize, sizeof(tagSize)) + sizeof(tagSize);
            memcpy(dest, tag, tagSize);
        }
    }
    return retval;
}

seos_err_t
SeosCryptoRpc_keyCreate(SeosCryptoRpc* self,
                        SeosCryptoCipher_Algorithm algorithm,
                        unsigned int flags,
                        size_t lenBits,
                        SeosCrypto_KeyHandle* pKeyHandle)
{
    Debug_ASSERT_SELF(self);

    size_t      buffSize    = -1;
    seos_err_t  retval      = SeosCrypto_keyCreate(self->seosCryptoApiCtx,
                                                   algorithm,
                                                   flags,
                                                   lenBits,
                                                   pKeyHandle,
                                                   NULL,
                                                   &buffSize);
    return retval;
}
