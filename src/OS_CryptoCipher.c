/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibCipher.h"

#define PROXY_GET_PTR(p) \
    (CryptoLibCipher_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoCipher_init(
    OS_CryptoCipher_Handle_t*   hCipher,
    const OS_Crypto_Handle_t    self,
    const OS_CryptoKey_Handle_t hKey,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    const size_t                ivSize)
{
    seos_err_t err;

    PROXY_INIT(*hCipher, self);
    if ((err = PROXY_CALL(*hCipher, Cipher_init, PROXY_GET_PTR(*hCipher),
                          algorithm, PROXY_GET_OBJ(hKey), iv, ivSize)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hCipher);
    }

    return err;
}

seos_err_t
OS_CryptoCipher_free(
    OS_CryptoCipher_Handle_t hCipher)
{
    seos_err_t err;

    err = PROXY_CALL(hCipher, Cipher_free, PROXY_GET_OBJ(hCipher));
    PROXY_FREE(hCipher);

    return err;
}

seos_err_t
OS_CryptoCipher_process(
    OS_CryptoCipher_Handle_t hCipher,
    const void*              input,
    const size_t             inputSize,
    void*                    output,
    size_t*                  outputSize)
{
    return PROXY_CALL(hCipher, Cipher_process, PROXY_GET_OBJ(hCipher), input,
                      inputSize, output, outputSize);
}

seos_err_t
OS_CryptoCipher_start(
    OS_CryptoCipher_Handle_t hCipher,
    const void*              ad,
    const size_t             adSize)
{
    return PROXY_CALL(hCipher, Cipher_start, PROXY_GET_OBJ(hCipher), ad, adSize);
}

seos_err_t
OS_CryptoCipher_finalize(
    OS_CryptoCipher_Handle_t hCipher,
    void*                    output,
    size_t*                  outputSize)
{
    return PROXY_CALL(hCipher, Cipher_finalize, PROXY_GET_OBJ(hCipher), output,
                      outputSize);
}