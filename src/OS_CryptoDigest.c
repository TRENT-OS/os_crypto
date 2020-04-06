/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibDigest.h"

#define PROXY_GET_PTR(p) \
    (OS_CryptoLibDigest_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoDigest_init(
    OS_CryptoDigest_Handle_t*   hDigest,
    const OS_Crypto_Handle_t    self,
    const OS_CryptoDigest_Alg_t algorithm)
{
    seos_err_t err;

    PROXY_INIT(*hDigest, self);
    if ((err = PROXY_CALL(*hDigest, Digest_init, PROXY_GET_PTR(*hDigest),
                          algorithm)) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hDigest);
    }

    return err;
}

seos_err_t
OS_CryptoDigest_free(
    OS_CryptoDigest_Handle_t hDigest)
{
    seos_err_t err;

    err = PROXY_CALL(hDigest, Digest_free, PROXY_GET_OBJ(hDigest));
    PROXY_FREE(hDigest);

    return err;
}

seos_err_t
OS_CryptoDigest_clone(
    OS_CryptoDigest_Handle_t       hDstDigest,
    const OS_CryptoDigest_Handle_t hSrcDigest)
{
    return PROXY_CALL(hDstDigest, Digest_clone, PROXY_GET_OBJ(hDstDigest),
                      PROXY_GET_OBJ(hSrcDigest));
}

seos_err_t
OS_CryptoDigest_process(
    OS_CryptoDigest_Handle_t hDigest,
    const void*              data,
    const size_t             dataSize)
{
    return PROXY_CALL(hDigest, Digest_process, PROXY_GET_OBJ(hDigest), data,
                      dataSize);
}

seos_err_t
OS_CryptoDigest_finalize(
    OS_CryptoDigest_Handle_t hDigest,
    void*                    digest,
    size_t*                  digestSize)
{
    return PROXY_CALL(hDigest, Digest_finalize, PROXY_GET_OBJ(hDigest), digest,
                      digestSize);
}