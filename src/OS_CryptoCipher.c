/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"
#include "lib_macros/Check.h"

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

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);
    CHECK_PTR_NOT_NULL(hKey);

    PROXY_INIT_FROM_KEY(*self, hKey);
    if ((err = PROXY_CALL(*self, Cipher_init, PROXY_GET_OBJ_PTR(*self),
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

    CHECK_PTR_NOT_NULL(self);

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
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Cipher_process, PROXY_GET_OBJ(self), input,
                      inputSize, output, outputSize);
}

OS_Error_t
OS_CryptoCipher_start(
    OS_CryptoCipher_Handle_t self,
    const void*              ad,
    const size_t             adSize)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Cipher_start, PROXY_GET_OBJ(self), ad, adSize);
}

OS_Error_t
OS_CryptoCipher_finalize(
    OS_CryptoCipher_Handle_t self,
    void*                    output,
    size_t*                  outputSize)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Cipher_finalize, PROXY_GET_OBJ(self), output,
                      outputSize);
}