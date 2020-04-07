/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibKey.h"

#define PROXY_GET_PTR(p) \
    (CryptoLibKey_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoKey_generate(
    OS_CryptoKey_Handle_t*     self,
    const OS_Crypto_Handle_t   hCrypto,
    const OS_CryptoKey_Spec_t* spec)
{
    seos_err_t err;

    PROXY_INIT(*self, hCrypto);
    if ((err = PROXY_CALL(*self, Key_generate, PROXY_GET_PTR(*self),
                          spec)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

seos_err_t
OS_CryptoKey_import(
    OS_CryptoKey_Handle_t*     self,
    const OS_Crypto_Handle_t   hCrypto,
    const OS_CryptoKey_Data_t* keyData)
{
    seos_err_t err;

    PROXY_INIT(*self, hCrypto);
    if ((err = PROXY_CALL(*self, Key_import, PROXY_GET_PTR(*self),
                          keyData)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

seos_err_t
OS_CryptoKey_makePublic(
    OS_CryptoKey_Handle_t*       self,
    const OS_Crypto_Handle_t     hCrypto,
    const OS_CryptoKey_Handle_t  hPrvKey,
    const OS_CryptoKey_Attrib_t* attribs)
{
    seos_err_t err;

    PROXY_INIT(*self, hCrypto);
    if ((err = PROXY_CALL(*self, Key_makePublic, PROXY_GET_PTR(*self),
                          PROXY_GET_OBJ(hPrvKey), attribs)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

seos_err_t
OS_CryptoKey_free(
    OS_CryptoKey_Handle_t self)
{
    return PROXY_CALL(self, Key_free, PROXY_GET_OBJ(self));
}

seos_err_t
OS_CryptoKey_export(
    const OS_CryptoKey_Handle_t self,
    OS_CryptoKey_Data_t*        keyData)
{
    return PROXY_CALL(self, Key_export, PROXY_GET_OBJ(self), keyData);
}

seos_err_t
OS_CryptoKey_getParams(
    const OS_CryptoKey_Handle_t self,
    void*                       keyParams,
    size_t*                     paramSize)
{
    return PROXY_CALL(self, Key_getParams, PROXY_GET_OBJ(self), keyParams,
                      paramSize);
}

seos_err_t
OS_CryptoKey_getAttribs(
    const OS_CryptoKey_Handle_t self,
    OS_CryptoKey_Attrib_t*      attribs)
{
    return PROXY_CALL(self, Key_getAttribs, PROXY_GET_OBJ(self), attribs);
}

seos_err_t
OS_CryptoKey_loadParams(
    OS_Crypto_Handle_t         hCrypto,
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    return CALL(hCrypto, Key_loadParams, name, keyParams, paramSize);
}