/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibKey.h"

#define PROXY_GET_PTR(p) \
    (OS_CryptoLibKey_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoKey_generate(
    OS_CryptoKey_Handle_t*     hKey,
    const OS_Crypto_Handle_t   self,
    const OS_CryptoKey_Spec_t* spec)
{
    seos_err_t err;

    PROXY_INIT(*hKey, self);
    if ((err = PROXY_CALL(*hKey, Key_generate, PROXY_GET_PTR(*hKey),
                          spec)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hKey);
    }

    return err;
}

seos_err_t
OS_CryptoKey_import(
    OS_CryptoKey_Handle_t*     hKey,
    const OS_Crypto_Handle_t   self,
    const OS_CryptoKey_Data_t* keyData)
{
    seos_err_t err;

    PROXY_INIT(*hKey, self);
    if ((err = PROXY_CALL(*hKey, Key_import, PROXY_GET_PTR(*hKey),
                          keyData)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hKey);
    }

    return err;
}

seos_err_t
OS_CryptoKey_makePublic(
    OS_CryptoKey_Handle_t*       hPubKey,
    const OS_Crypto_Handle_t     self,
    const OS_CryptoKey_Handle_t  hPrvKey,
    const OS_CryptoKey_Attrib_t* attribs)
{
    seos_err_t err;

    PROXY_INIT(*hPubKey, self);
    if ((err = PROXY_CALL(*hPubKey, Key_makePublic, PROXY_GET_PTR(*hPubKey),
                          PROXY_GET_OBJ(hPrvKey), attribs)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hPubKey);
    }

    return err;
}

seos_err_t
OS_CryptoKey_free(
    OS_CryptoKey_Handle_t hKey)
{
    return PROXY_CALL(hKey, Key_free, PROXY_GET_OBJ(hKey));
}

seos_err_t
OS_CryptoKey_export(
    const OS_CryptoKey_Handle_t hKey,
    OS_CryptoKey_Data_t*        keyData)
{
    return PROXY_CALL(hKey, Key_export, PROXY_GET_OBJ(hKey), keyData);
}

seos_err_t
OS_CryptoKey_getParams(
    const OS_CryptoKey_Handle_t hKey,
    void*                       keyParams,
    size_t*                     paramSize)
{
    return PROXY_CALL(hKey, Key_getParams, PROXY_GET_OBJ(hKey), keyParams,
                      paramSize);
}

seos_err_t
OS_CryptoKey_getAttribs(
    const OS_CryptoKey_Handle_t hKey,
    OS_CryptoKey_Attrib_t*      attribs)
{
    return PROXY_CALL(hKey, Key_getAttribs, PROXY_GET_OBJ(hKey), attribs);
}

seos_err_t
OS_CryptoKey_loadParams(
    OS_Crypto_Handle_t         self,
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    return CALL(self, Key_loadParams, name, keyParams, paramSize);
}