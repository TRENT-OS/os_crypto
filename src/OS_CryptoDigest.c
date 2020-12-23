/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#include "lib_macros/Check.h"

OS_Error_t
OS_CryptoDigest_init(
    OS_CryptoDigest_Handle_t*   self,
    const OS_Crypto_Handle_t    hCrypto,
    const OS_CryptoDigest_Alg_t algorithm)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_CLIENT);
    if ((err = PROXY_CALL(*self, Digest_init, PROXY_GET_OBJ_PTR(*self),
                          algorithm)) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoDigest_clone(
    OS_CryptoDigest_Handle_t*      self,
    const OS_Crypto_Handle_t       hCrypto,
    const OS_CryptoDigest_Handle_t hSrcDigest)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);
    CHECK_PTR_NOT_NULL(hSrcDigest);

    PROXY_INIT(*self, hCrypto, hCrypto->mode == OS_Crypto_MODE_CLIENT);
    if ((err = PROXY_CALL(*self, Digest_clone, PROXY_GET_OBJ_PTR(*self),
                          PROXY_GET_OBJ(hSrcDigest))) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoDigest_free(
    OS_CryptoDigest_Handle_t self)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);

    err = PROXY_CALL(self, Digest_free, PROXY_GET_OBJ(self));
    PROXY_FREE(self);

    return err;
}

OS_Error_t
OS_CryptoDigest_process(
    OS_CryptoDigest_Handle_t self,
    const void*              data,
    const size_t             dataSize)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Digest_process, PROXY_GET_OBJ(self), data,
                      dataSize);
}

OS_Error_t
OS_CryptoDigest_finalize(
    OS_CryptoDigest_Handle_t self,
    void*                    digest,
    size_t*                  digestSize)
{
    CHECK_PTR_NOT_NULL(self);

    return PROXY_CALL(self, Digest_finalize, PROXY_GET_OBJ(self), digest,
                      digestSize);
}