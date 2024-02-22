/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#include "lib_macros/Check.h"

OS_Error_t
OS_CryptoKey_generate(
    OS_CryptoKey_Handle_t*     self,
    const OS_Crypto_Handle_t   hCrypto,
    const OS_CryptoKey_Spec_t* spec)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);
    CHECK_PTR_NOT_NULL(spec);

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_CLIENT
               || (hCrypto->mode == OS_Crypto_MODE_KEY_SWITCH &&
                   !spec->key.attribs.keepLocal));
    if ((err = PROXY_CALL(*self, Key_generate, PROXY_GET_OBJ_PTR(*self),
                          spec)) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoKey_import(
    OS_CryptoKey_Handle_t*     self,
    const OS_Crypto_Handle_t   hCrypto,
    const OS_CryptoKey_Data_t* keyData)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);
    CHECK_PTR_NOT_NULL(keyData);

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_CLIENT
               || (hCrypto->mode == OS_Crypto_MODE_KEY_SWITCH &&
                   !keyData->attribs.keepLocal));
    if ((err = PROXY_CALL(*self, Key_import, PROXY_GET_OBJ_PTR(*self),
                          keyData)) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoKey_makePublic(
    OS_CryptoKey_Handle_t*       self,
    const OS_Crypto_Handle_t     hCrypto,
    const OS_CryptoKey_Handle_t  hPrvKey,
    const OS_CryptoKey_Attrib_t* attribs)
{
    OS_CryptoKey_Attrib_t srcAttribs;
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);
    CHECK_PTR_NOT_NULL(hPrvKey);
    CHECK_PTR_NOT_NULL(attribs);

    if ((err = PROXY_CALL(hPrvKey, Key_getAttribs, PROXY_GET_OBJ(hPrvKey),
                          &srcAttribs)) != OS_SUCCESS)
    {
        return err;
    }

    /*
     * For now we need to make sure both keys are kept in the same address space;
     * this is only relevant in CLIENT mode, where the attribute is evaluated..
     *
     * We could enable some of the cases where locality differs by simply
     * creating a temporary copy of the src/dst key to execute the makePublic()
     * and then putting it in the correct address space.
     */
    if (hCrypto->mode == OS_Crypto_MODE_KEY_SWITCH &&
        attribs->keepLocal != srcAttribs.keepLocal)
    {
        return OS_ERROR_NOT_SUPPORTED;
    }

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_CLIENT
               || (hCrypto->mode == OS_Crypto_MODE_KEY_SWITCH &&
                   !attribs->keepLocal));
    if ((err = PROXY_CALL(*self, Key_makePublic, PROXY_GET_OBJ_PTR(*self),
                          PROXY_GET_OBJ(hPrvKey), attribs)) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoKey_free(
    OS_CryptoKey_Handle_t self)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Key_free, PROXY_GET_OBJ(self));
}

OS_Error_t
OS_CryptoKey_export(
    const OS_CryptoKey_Handle_t self,
    OS_CryptoKey_Data_t*        keyData)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Key_export, PROXY_GET_OBJ(self), keyData);
}

OS_Error_t
OS_CryptoKey_getParams(
    const OS_CryptoKey_Handle_t self,
    void*                       keyParams,
    size_t*                     paramSize)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Key_getParams, PROXY_GET_OBJ(self), keyParams,
                      paramSize);
}

OS_Error_t
OS_CryptoKey_getAttribs(
    const OS_CryptoKey_Handle_t self,
    OS_CryptoKey_Attrib_t*      attribs)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Key_getAttribs, PROXY_GET_OBJ(self), attribs);
}

OS_Error_t
OS_CryptoKey_loadParams(
    OS_Crypto_Handle_t         hCrypto,
    const OS_CryptoKey_Param_t name,
    void*                      keyParams,
    size_t*                    paramSize)
{
    CHECK_PTR_NOT_NULL(hCrypto);

    return CALL(hCrypto, Key_loadParams, name, keyParams, paramSize);
}