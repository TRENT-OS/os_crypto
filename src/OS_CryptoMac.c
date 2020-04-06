/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibMac.h"

#define PROXY_GET_PTR(p) \
    (OS_CryptoLibMac_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoMac_init(
    OS_CryptoMac_Handle_t*   hMac,
    const OS_Crypto_Handle_t self,
    const OS_CryptoMac_Alg_t algorithm)
{
    seos_err_t err;

    PROXY_INIT(*hMac, self);
    if ((err = PROXY_CALL(*hMac, Mac_init, PROXY_GET_PTR(*hMac),
                          algorithm)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hMac);
    }

    return err;
}

seos_err_t
OS_CryptoMac_free(
    OS_CryptoMac_Handle_t hMac)
{
    seos_err_t err;

    err = PROXY_CALL(hMac, Mac_free, PROXY_GET_OBJ(hMac));
    PROXY_FREE(hMac);

    return err;
}

seos_err_t
OS_CryptoMac_start(
    OS_CryptoMac_Handle_t hMac,
    const void*           secret,
    const size_t          secretSize)
{
    return PROXY_CALL(hMac, Mac_start, PROXY_GET_OBJ(hMac), secret, secretSize);
}

seos_err_t
OS_CryptoMac_process(
    OS_CryptoMac_Handle_t hMac,
    const void*           data,
    const size_t          dataSize)
{
    return PROXY_CALL(hMac, Mac_process, PROXY_GET_OBJ(hMac), data, dataSize);
}

seos_err_t
OS_CryptoMac_finalize(
    OS_CryptoMac_Handle_t hMac,
    void*                 mac,
    size_t*               macSize)
{
    return PROXY_CALL(hMac, Mac_finalize, PROXY_GET_OBJ(hMac), mac, macSize);
}