/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#include "lib_macros/Check.h"

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

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);

    if (NULL == hPrvKey && NULL == hPubKey)
    {
        Debug_LOG_ERROR("Must at least have non-NULL private or "
                        "public key");
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (NULL != hPrvKey && NULL != hPubKey
        && (hPrvKey->impl->context != hPubKey->impl->context
            || hPrvKey->impl->vtable != hPubKey->impl->vtable))
    {
        Debug_LOG_ERROR("Given keys are not managed by the same library "
                        "instance, this may be because one is local and "
                        "the other in a remote component");
        return OS_ERROR_INVALID_PARAMETER;
    }

    key = (hPubKey != NULL) ? hPubKey : hPrvKey;
    PROXY_INIT_FROM_KEY(*self, key);
    if ((err = PROXY_CALL(*self, Signature_init, PROXY_GET_OBJ_PTR(*self),
                          PROXY_GET_OBJ(hPrvKey), PROXY_GET_OBJ(hPubKey),
                          sigAlgorithm, digAlgorithm)) != OS_SUCCESS)
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

    CHECK_PTR_NOT_NULL(self);

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
    CHECK_PTR_NOT_NULL(self);

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
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Signature_verify, PROXY_GET_OBJ(self), hash, hashSize,
                      signature, signatureSize);
}