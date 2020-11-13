/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#include "LibMacros/Check.h"

OS_Error_t
OS_CryptoMac_init(
    OS_CryptoMac_Handle_t*      self,
    const OS_Crypto_Handle_t    hCrypto,
    const OS_CryptoKey_Handle_t hKey,
    const OS_CryptoMac_Alg_t    algorithm)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(hCrypto);

    PROXY_INIT_FROM_KEY(*self, hKey);
    if ((err = PROXY_CALL(*self, Mac_init, PROXY_GET_OBJ_PTR(*self),
                          PROXY_GET_OBJ(hKey), algorithm)) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoMac_free(
    OS_CryptoMac_Handle_t self)
{
    OS_Error_t err;

    err = PROXY_CALL(self, Mac_free, PROXY_GET_OBJ(self));
    PROXY_FREE(self);

    return err;
}

OS_Error_t
OS_CryptoMac_process(
    OS_CryptoMac_Handle_t self,
    const void*           data,
    const size_t          dataSize)
{
    return PROXY_CALL(self, Mac_process, PROXY_GET_OBJ(self), data, dataSize);
}

OS_Error_t
OS_CryptoMac_finalize(
    OS_CryptoMac_Handle_t self,
    void*                 mac,
    size_t*               macSize)
{
    return PROXY_CALL(self, Mac_finalize, PROXY_GET_OBJ(self), mac, macSize);
}