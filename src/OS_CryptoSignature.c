/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibSignature.h"

#define PROXY_GET_PTR(p) \
    (CryptoLibSignature_t**) PROXY_GET_OBJ_PTR(p)

OS_Error_t
OS_CryptoSignature_init(
    OS_CryptoSignature_Handle_t*   self,
    const OS_Crypto_Handle_t       hCrypto,
    const OS_CryptoKey_Handle_t    hPrvKey,
    const OS_CryptoKey_Handle_t    hPubKey,
    const OS_CryptoSignature_Alg_t sigAlgorithm,
    const OS_CryptoDigest_Alg_t    digAlgorithm)
{
    OS_CryptoKey_Handle_t key;
    OS_Error_t err;

    // We are actually not using this; lets check it anyways for consistency.
    if (NULL == hCrypto)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (NULL == hPrvKey && NULL == hPubKey)
    {
        // We should at least have one key
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL != hPrvKey && NULL != hPubKey
             && (hPrvKey->impl->context != hPubKey->impl->context
                 || hPrvKey->impl->vtable != hPubKey->impl->vtable))
    {
        // If we have two keys, we need to make sure that they are both associated
        // with the same LIB instance
        return SEOS_ERROR_INVALID_HANDLE;
    }

    key = (hPubKey != NULL) ? hPubKey : hPrvKey;
    PROXY_INIT_FROM_KEY(*self, key);
    if ((err = PROXY_CALL(*self, Signature_init, PROXY_GET_PTR(*self),
                          PROXY_GET_OBJ(hPrvKey), PROXY_GET_OBJ(hPubKey),
                          sigAlgorithm, digAlgorithm)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoSignature_free(
    OS_CryptoSignature_Handle_t self)
{
    OS_Error_t err;

    err = PROXY_CALL(self, Signature_free, PROXY_GET_OBJ(self));
    PROXY_FREE(self);

    return err;
}

OS_Error_t
OS_CryptoSignature_sign(
    OS_CryptoSignature_Handle_t self,
    const void*                 hash,
    const size_t                hashSize,
    void*                       signature,
    size_t*                     signatureSize)
{
    return PROXY_CALL(self, Signature_sign, PROXY_GET_OBJ(self), hash, hashSize,
                      signature, signatureSize);
}

OS_Error_t
OS_CryptoSignature_verify(
    OS_CryptoSignature_Handle_t self,
    const void*                 hash,
    const size_t                hashSize,
    const void*                 signature,
    const size_t                signatureSize)
{
    return PROXY_CALL(self, Signature_verify, PROXY_GET_OBJ(self), hash, hashSize,
                      signature, signatureSize);
}