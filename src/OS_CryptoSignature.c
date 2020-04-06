/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibSignature.h"

#define PROXY_GET_PTR(p) \
    (CryptoLibSignature_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoSignature_init(
    OS_CryptoSignature_Handle_t*   hSig,
    const OS_Crypto_Handle_t       self,
    const OS_CryptoKey_Handle_t    hPrvKey,
    const OS_CryptoKey_Handle_t    hPubKey,
    const OS_CryptoSignature_Alg_t sigAlgorithm,
    const OS_CryptoDigest_Alg_t    digAlgorithm)
{
    seos_err_t err;

    PROXY_INIT(*hSig, self);
    if ((err = PROXY_CALL(*hSig, Signature_init, PROXY_GET_PTR(*hSig),
                          sigAlgorithm, digAlgorithm,
                          PROXY_GET_OBJ(hPrvKey), PROXY_GET_OBJ(hPubKey))) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hSig);
    }

    return err;
}

seos_err_t
OS_CryptoSignature_free(
    OS_CryptoSignature_Handle_t hSig)
{
    seos_err_t err;

    err = PROXY_CALL(hSig, Signature_free, PROXY_GET_OBJ(hSig));
    PROXY_FREE(hSig);

    return err;
}

seos_err_t
OS_CryptoSignature_sign(
    OS_CryptoSignature_Handle_t hSig,
    const void*                 hash,
    const size_t                hashSize,
    void*                       signature,
    size_t*                     signatureSize)
{
    return PROXY_CALL(hSig, Signature_sign, PROXY_GET_OBJ(hSig), hash, hashSize,
                      signature, signatureSize);
}

seos_err_t
OS_CryptoSignature_verify(
    OS_CryptoSignature_Handle_t hSig,
    const void*                 hash,
    const size_t                hashSize,
    const void*                 signature,
    const size_t                signatureSize)
{
    return PROXY_CALL(hSig, Signature_verify, PROXY_GET_OBJ(hSig), hash, hashSize,
                      signature, signatureSize);
}