/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_CRYPTO_WITH_RPC_CLIENT)

#include "SeosCryptoRpc_Client.h"
#include "SeosCryptoRpc_Server.h"

#include "SeosCryptoVtable.h"

#include <string.h>
#include <sys/user.h>

// -------------------------------- RNG API ------------------------------------

static seos_err_t
Rng_getBytes(
    void*                        ctx,
    const SeosCryptoApi_Rng_Flag flags,
    void*                        buf,
    const size_t                 bufSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == buf)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (bufSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoRpc_Server_Rng_getBytes(self->api, flags,
                                                 bufSize)) == SEOS_SUCCESS)
    {
        memcpy(buf, self->dataPort, bufSize);
    }

    return err;
}

static seos_err_t
Rng_reseed(
    void*        ctx,
    const void*  seed,
    const size_t seedSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == seed)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (seedSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, seed, seedSize);
    return SeosCryptoRpc_Server_Rng_reseed(self->api, seedSize);
}

// ------------------------------- MAC API -------------------------------------

static seos_err_t
Mac_init(
    void*                       ctx,
    SeosCryptoLib_Mac**         pMacObj,
    const SeosCryptoApi_Mac_Alg algorithm)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == pMacObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Mac_init(self->api, pMacObj, algorithm);
}

static seos_err_t
Mac_exists(
    void*                    ctx,
    const SeosCryptoLib_Mac* macObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    return (NULL == self) ?
           SEOS_ERROR_INVALID_PARAMETER :
           SeosCryptoRpc_Server_Mac_exists(self->api, macObj);
}

static seos_err_t
Mac_free(
    void*              ctx,
    SeosCryptoLib_Mac* macObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Mac_free(self->api, macObj);
}

static seos_err_t
Mac_start(
    void*              ctx,
    SeosCryptoLib_Mac* macObj,
    const void*        secret,
    const size_t       secretSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == secret)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (secretSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, secret, secretSize);
    return SeosCryptoRpc_Server_Mac_start(self->api, macObj, secretSize);
}

static seos_err_t
Mac_process(
    void*              ctx,
    SeosCryptoLib_Mac* macObj,
    const void*        data,
    const size_t       dataSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, data, dataSize);
    return SeosCryptoRpc_Server_Mac_process(self->api, macObj, dataSize);
}

static seos_err_t
Mac_finalize(
    void*              ctx,
    SeosCryptoLib_Mac* macObj,
    void*              mac,
    size_t*            macSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == mac || NULL == macSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*macSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoRpc_Server_Mac_finalize(self->api, macObj,
                                                 macSize)) == SEOS_SUCCESS)
    {
        memcpy(mac, self->dataPort, *macSize);
    }

    return err;
}

// ------------------------------ Digest API -----------------------------------

static seos_err_t
Digest_init(
    void*                          ctx,
    SeosCryptoLib_Digest**         pDigestObj,
    const SeosCryptoApi_Digest_Alg algorithm)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == pDigestObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Digest_init(self->api, pDigestObj, algorithm);
}

static seos_err_t
Digest_exists(
    void*                       ctx,
    const SeosCryptoLib_Digest* digestObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    return (NULL == self) ?
           SEOS_ERROR_INVALID_PARAMETER :
           SeosCryptoRpc_Server_Digest_exists(self->api, digestObj);
}

static seos_err_t
Digest_free(
    void*                 ctx,
    SeosCryptoLib_Digest* digestObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Digest_free(self->api, digestObj);
}

static seos_err_t
Digest_clone(
    void*                       ctx,
    SeosCryptoLib_Digest*       dstDigObj,
    const SeosCryptoLib_Digest* srcDigObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Digest_clone(self->api, dstDigObj,
                                             srcDigObj);
}

static seos_err_t
Digest_process(
    void*                 ctx,
    SeosCryptoLib_Digest* digestObj,
    const void*           data,
    const size_t          dataSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, data, dataSize);
    return SeosCryptoRpc_Server_Digest_process(self->api, digestObj, dataSize);
}

static seos_err_t
Digest_finalize(
    void*                 ctx,
    SeosCryptoLib_Digest* digestObj,
    void*                 digest,
    size_t*               digestSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == digest || NULL == digestSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*digestSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoRpc_Server_Digest_finalize(self->api, digestObj,
                                                    digestSize)) == SEOS_SUCCESS)
    {
        memcpy(digest, self->dataPort, *digestSize);
    }

    return err;
}

// ----------------------------- Signature API ---------------------------------

static seos_err_t
Signature_init(
    void*                             ctx,
    SeosCryptoLib_Signature**         pSigObj,
    const SeosCryptoApi_Signature_Alg algorithm,
    const SeosCryptoApi_Digest_Alg    digest,
    const SeosCryptoLib_Key*          prvKey,
    const SeosCryptoLib_Key*          pubKey)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == pSigObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Signature_init(self->api, pSigObj, algorithm,
                                               digest, prvKey, pubKey);
}

static seos_err_t
Signature_exists(
    void*                          ctx,
    const SeosCryptoLib_Signature* signatureObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    return (NULL == self) ?
           SEOS_ERROR_INVALID_PARAMETER :
           SeosCryptoRpc_Server_Signature_exists(self->api, signatureObj);
}

static seos_err_t
Signature_free(
    void*                    ctx,
    SeosCryptoLib_Signature* sigObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Signature_free(self->api, sigObj);
}

static seos_err_t
Signature_sign(
    void*                    ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    void*                    signature,
    size_t*                  signatureSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == hash || NULL == signature || NULL == signatureSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    else if (*signatureSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, hash, hashSize);
    if ((err = SeosCryptoRpc_Server_Signature_sign(self->api, sigObj,
                                                   hashSize, signatureSize)) == SEOS_SUCCESS)
    {
        memcpy(signature, self->dataPort, *signatureSize);
    }

    return err;
}

static seos_err_t
Signature_verify(
    void*                    ctx,
    SeosCryptoLib_Signature* sigObj,
    const void*              hash,
    const size_t             hashSize,
    const void*              signature,
    const size_t             signatureSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == hash || NULL == signature)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (hashSize + signatureSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, hash, hashSize);
    memcpy(self->dataPort + hashSize, signature, signatureSize);
    return SeosCryptoRpc_Server_Signature_verify(self->api, sigObj, hashSize,
                                                 signatureSize);
}

// ----------------------------- Agreement API ---------------------------------

static seos_err_t
Agreement_init(
    void*                             ctx,
    SeosCryptoLib_Agreement**         pAgrObj,
    const SeosCryptoApi_Agreement_Alg algorithm,
    const SeosCryptoLib_Key*          prvKey)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == pAgrObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Agreement_init(self->api, pAgrObj, algorithm,
                                               prvKey);
}

static seos_err_t
Agreement_exists(
    void*                          ctx,
    const SeosCryptoLib_Agreement* agrObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    return (NULL == self) ?
           SEOS_ERROR_INVALID_PARAMETER :
           SeosCryptoRpc_Server_Agreement_exists(self->api, agrObj);
}

static seos_err_t
Agreement_free(
    void*                    ctx,
    SeosCryptoLib_Agreement* agrObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Agreement_free(self->api, agrObj);
}

static seos_err_t
Agreement_agree(
    void*                    ctx,
    SeosCryptoLib_Agreement* agrObj,
    const SeosCryptoLib_Key* pubKey,
    void*                    shared,
    size_t*                  sharedSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == ctx || NULL == shared || NULL == sharedSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*sharedSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoRpc_Server_Agreement_agree(self->api, agrObj,
                                                    pubKey, sharedSize)) == SEOS_SUCCESS)
    {
        memcpy(shared, self->dataPort, *sharedSize);
    }

    return err;
}

// -------------------------------- Key API ------------------------------------

static seos_err_t
Key_generate(
    void*                         ctx,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Spec* spec)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self || NULL == pKeyObj || NULL == spec)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->dataPort, spec, sizeof(SeosCryptoApi_Key_Spec));
    return SeosCryptoRpc_Server_Key_generate(self->api, pKeyObj);
}

static seos_err_t
Key_makePublic(
    void*                            ctx,
    SeosCryptoLib_Key**              pPubKeyObj,
    const SeosCryptoLib_Key*         prvKeyObj,
    const SeosCryptoApi_Key_Attribs* attribs)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self || NULL == pPubKeyObj || NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->dataPort, attribs, sizeof(SeosCryptoApi_Key_Attribs));
    return SeosCryptoRpc_Server_Key_makePublic(self->api, pPubKeyObj,
                                               prvKeyObj);
}

static seos_err_t
Key_import(
    void*                         ctx,
    SeosCryptoLib_Key**           pKeyObj,
    const SeosCryptoApi_Key_Data* keyData)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self || NULL == pKeyObj || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->dataPort, keyData, sizeof(SeosCryptoApi_Key_Data));
    return SeosCryptoRpc_Server_Key_import(self->api, pKeyObj);
}

static seos_err_t
Key_export(
    void*                    ctx,
    const SeosCryptoLib_Key* keyObj,
    SeosCryptoApi_Key_Data*  keyData)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = SeosCryptoRpc_Server_Key_export(self->api, keyObj)) == SEOS_SUCCESS)
    {
        memcpy(keyData, self->dataPort, sizeof(SeosCryptoApi_Key_Data));
    }

    return err;
}

static seos_err_t
Key_getParams(
    void*                    ctx,
    const SeosCryptoLib_Key* keyObj,
    void*                    keyParams,
    size_t*                  paramSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoRpc_Server_Key_getParams(self->api, keyObj,
                                                  paramSize)) == SEOS_SUCCESS)
    {
        memcpy(keyParams, self->dataPort, *paramSize);
    }

    return err;
}

static seos_err_t
Key_getAttribs(
    void*                      ctx,
    const SeosCryptoLib_Key*   keyObj,
    SeosCryptoApi_Key_Attribs* attribs)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == attribs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((err = SeosCryptoRpc_Server_Key_getAttribs(self->api,
                                                   keyObj)) == SEOS_SUCCESS)
    {
        memcpy(attribs, self->dataPort, sizeof(SeosCryptoApi_Key_Attribs));
    }

    return err;
}

static seos_err_t
Key_loadParams(
    void*                         ctx,
    const SeosCryptoApi_Key_Param name,
    void*                         keyParams,
    size_t*                       paramSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyParams || NULL == paramSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*paramSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = SeosCryptoRpc_Server_Key_loadParams(self->api, name,
                                                   paramSize)) == SEOS_SUCCESS)
    {
        memcpy(keyParams, self->dataPort, *paramSize);
    }

    return err;
}

static seos_err_t
Key_exists(
    void*                    ctx,
    const SeosCryptoLib_Key* keyObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    return (NULL == self) ?
           SEOS_ERROR_INVALID_PARAMETER :
           SeosCryptoRpc_Server_Key_exists(self->api, keyObj);
}

static seos_err_t
Key_free(
    void*              ctx,
    SeosCryptoLib_Key* keyObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Key_free(self->api, keyObj);
}

// ------------------------------ Cipher API -----------------------------------

static seos_err_t
Cipher_init(
    void*                          ctx,
    SeosCryptoLib_Cipher**         pCipherObj,
    const SeosCryptoApi_Cipher_Alg algorithm,
    const SeosCryptoLib_Key*       key,
    const void*                    iv,
    const size_t                   ivSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self || NULL == pCipherObj)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (iv != NULL)
    {
        if (ivSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->dataPort, iv, ivSize);
    }

    return SeosCryptoRpc_Server_Cipher_init(self->api, pCipherObj, algorithm,
                                            key, ivSize);
}

static seos_err_t
Cipher_exists(
    void*                       ctx,
    const SeosCryptoLib_Cipher* cipherObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;
    return (NULL == self) ?
           SEOS_ERROR_INVALID_PARAMETER :
           SeosCryptoRpc_Server_Cipher_exists(self->api, cipherObj);
}

static seos_err_t
Cipher_free(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosCryptoRpc_Server_Cipher_free(self->api, cipherObj);
}

static seos_err_t
Cipher_process(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           input,
    const size_t          inputSize,
    void*                 output,
    size_t*               outputSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self || NULL == input || NULL == output || NULL == outputSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (inputSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    else if (*outputSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, input, inputSize);
    if ((err = SeosCryptoRpc_Server_Cipher_process(self->api, cipherObj,
                                                   inputSize, outputSize)) == SEOS_SUCCESS)
    {
        memcpy(output, self->dataPort, *outputSize);
    }

    return err;
}

static seos_err_t
Cipher_start(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj,
    const void*           data,
    const size_t          dataSize)
{
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL != data)
    {
        if (dataSize > SeosCryptoApi_SIZE_DATAPORT)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        memcpy(self->dataPort, data, dataSize);
    }

    return SeosCryptoRpc_Server_Cipher_start(self->api, cipherObj, dataSize);
}

static seos_err_t
Cipher_finalize(
    void*                 ctx,
    SeosCryptoLib_Cipher* cipherObj,
    void*                 tag,
    size_t*               tagSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoRpc_Client* self = (SeosCryptoRpc_Client*) ctx;

    if (NULL == self || NULL == tag || NULL == tagSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (*tagSize > SeosCryptoApi_SIZE_DATAPORT)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataPort, tag, *tagSize);
    if ((err = SeosCryptoRpc_Server_Cipher_finalize(self->api, cipherObj,
                                                    tagSize)) == SEOS_SUCCESS)
    {
        memcpy(tag, self->dataPort, *tagSize);
    }

    return err;
}

// ------------------------------- init/free -----------------------------------

static const SeosCryptoVtable SeosCryptoRpc_Client_vtable =
{
    .Rng_getBytes        = Rng_getBytes,
    .Rng_reseed          = Rng_reseed,
    .Mac_init            = Mac_init,
    .Mac_exists          = Mac_exists,
    .Mac_free            = Mac_free,
    .Mac_start           = Mac_start,
    .Mac_process         = Mac_process,
    .Mac_finalize        = Mac_finalize,
    .Digest_init         = Digest_init,
    .Digest_exists       = Digest_exists,
    .Digest_free         = Digest_free,
    .Digest_clone        = Digest_clone,
    .Digest_process      = Digest_process,
    .Digest_finalize     = Digest_finalize,
    .Key_generate        = Key_generate,
    .Key_makePublic      = Key_makePublic,
    .Key_import          = Key_import,
    .Key_export          = Key_export,
    .Key_getParams       = Key_getParams,
    .Key_getAttribs      = Key_getAttribs,
    .Key_loadParams      = Key_loadParams,
    .Key_exists          = Key_exists,
    .Key_free            = Key_free,
    .Signature_init      = Signature_init,
    .Signature_exists    = Signature_exists,
    .Signature_free      = Signature_free,
    .Signature_sign      = Signature_sign,
    .Signature_verify    = Signature_verify,
    .Agreement_init      = Agreement_init,
    .Agreement_exists    = Agreement_exists,
    .Agreement_free      = Agreement_free,
    .Agreement_agree     = Agreement_agree,
    .Cipher_init         = Cipher_init,
    .Cipher_exists       = Cipher_exists,
    .Cipher_free         = Cipher_free,
    .Cipher_process      = Cipher_process,
    .Cipher_start        = Cipher_start,
    .Cipher_finalize     = Cipher_finalize,
};

seos_err_t
SeosCryptoRpc_Client_init(
    SeosCryptoRpc_Client*                 self,
    const SeosCryptoVtable**              vtable,
    const SeosCryptoApi_RpcClient_Config* cfg)
{
    if (NULL == self || NULL == vtable || NULL == cfg || NULL == cfg->dataPort)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    self->dataPort  = cfg->dataPort;
    // API ptr can be NULL, if RpcServer can call into CryptoServer to get the
    // pointer to its context. Checks are thus delegated to the RpcServer
    self->api       = cfg->api;

    *vtable  = &SeosCryptoRpc_Client_vtable;

    return SEOS_SUCCESS;
}

seos_err_t
SeosCryptoRpc_Client_free(
    SeosCryptoRpc_Client* self)
{
    return SEOS_SUCCESS;
}

#endif /* SEOS_CRYPTO_WITH_RPC_CLIENT */