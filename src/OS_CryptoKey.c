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

    if (NULL == spec || hCrypto == NULL)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_RPC_CLIENT
               || (hCrypto->mode == OS_Crypto_MODE_ROUTER &&
                   !spec->key.attribs.exportable));
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

    if (NULL == keyData || hCrypto == NULL)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_RPC_CLIENT
               || (hCrypto->mode == OS_Crypto_MODE_ROUTER &&
                   !keyData->attribs.exportable));
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
    OS_CryptoKey_Attrib_t srcAttribs;
    seos_err_t err;

    if (NULL == attribs || hCrypto == NULL)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL == hPrvKey)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }
    else if ((err = PROXY_CALL(hPrvKey, Key_getAttribs, PROXY_GET_OBJ(hPrvKey),
                               &srcAttribs)) != SEOS_SUCCESS)
    {
        return err;
    }

    /*
     * For now we need to make sure both have the same "exportablity" when
     * running in router mode, because they have to live in the same address
     * space..
     * We could enable some of the cases where exportability differs by simply
     * creating a temporary copy of the src/dst key to execute the makePublic()
     * and then putting it in the correct address space.
     */
    if (hCrypto->mode == OS_Crypto_MODE_ROUTER &&
        attribs->exportable != srcAttribs.exportable)
    {
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_RPC_CLIENT
               || (hCrypto->mode == OS_Crypto_MODE_ROUTER &&
                   !attribs->exportable));
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