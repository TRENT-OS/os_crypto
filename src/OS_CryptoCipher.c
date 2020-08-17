/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#define PROXY_GET_PTR(p) \
    (CryptoLibCipher_t**) PROXY_GET_OBJ_PTR(p)

OS_Error_t
OS_CryptoCipher_init(
    OS_CryptoCipher_Handle_t*   self,
    const OS_Crypto_Handle_t    hCrypto,
    const OS_CryptoKey_Handle_t hKey,
    const OS_CryptoCipher_Alg_t algorithm,
    const void*                 iv,
    const size_t                ivSize)
{
    OS_Error_t err;

    // We are actually not using this; lets check it anyways for consistency.
    if (NULL == hCrypto)
    {
        return OS_ERROR_INVALID_HANDLE;
    }

    PROXY_INIT_FROM_KEY(*self, hKey);
    if ((err = PROXY_CALL(*self, Cipher_init, PROXY_GET_PTR(*self),
                          PROXY_GET_OBJ(hKey), algorithm, iv, ivSize)) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoCipher_free(
    OS_CryptoCipher_Handle_t self)
{
    OS_Error_t err;

    err = PROXY_CALL(self, Cipher_free, PROXY_GET_OBJ(self));
    PROXY_FREE(self);

    return err;
}

OS_Error_t
OS_CryptoCipher_process(
    OS_CryptoCipher_Handle_t self,
    const void*              input,
    const size_t             inputSize,
    void*                    output,
    size_t*                  outputSize)
{
    return PROXY_CALL(self, Cipher_process, PROXY_GET_OBJ(self), input,
                      inputSize, output, outputSize);
}

OS_Error_t
OS_CryptoCipher_start(
    OS_CryptoCipher_Handle_t self,
    const void*              ad,
    const size_t             adSize)
{
    return PROXY_CALL(self, Cipher_start, PROXY_GET_OBJ(self), ad, adSize);
}

OS_Error_t
OS_CryptoCipher_finalize(
    OS_CryptoCipher_Handle_t self,
    void*                    output,
    size_t*                  outputSize)
{
    return PROXY_CALL(self, Cipher_finalize, PROXY_GET_OBJ(self), output,
                      outputSize);
}