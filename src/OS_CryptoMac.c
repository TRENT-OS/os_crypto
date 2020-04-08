/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibMac.h"

#define PROXY_GET_PTR(p) \
    (CryptoLibMac_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoMac_init(
    OS_CryptoMac_Handle_t*   self,
    const OS_Crypto_Handle_t hCrypto,
    const OS_CryptoMac_Alg_t algorithm)
{
    seos_err_t err;

    if (NULL == hCrypto)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_CLIENT_ONLY);
    if ((err = PROXY_CALL(*self, Mac_init, PROXY_GET_PTR(*self),
                          algorithm)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

seos_err_t
OS_CryptoMac_free(
    OS_CryptoMac_Handle_t self)
{
    seos_err_t err;

    err = PROXY_CALL(self, Mac_free, PROXY_GET_OBJ(self));
    PROXY_FREE(self);

    return err;
}

seos_err_t
OS_CryptoMac_start(
    OS_CryptoMac_Handle_t self,
    const void*           secret,
    const size_t          secretSize)
{
    return PROXY_CALL(self, Mac_start, PROXY_GET_OBJ(self), secret, secretSize);
}

seos_err_t
OS_CryptoMac_process(
    OS_CryptoMac_Handle_t self,
    const void*           data,
    const size_t          dataSize)
{
    return PROXY_CALL(self, Mac_process, PROXY_GET_OBJ(self), data, dataSize);
}

seos_err_t
OS_CryptoMac_finalize(
    OS_CryptoMac_Handle_t self,
    void*                 mac,
    size_t*               macSize)
{
    return PROXY_CALL(self, Mac_finalize, PROXY_GET_OBJ(self), mac, macSize);
}