/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibAgreement.h"

#define PROXY_GET_PTR(p) \
    (CryptoLibAgreement_t**) PROXY_GET_OBJ_PTR(p)

seos_err_t
OS_CryptoAgreement_init(
    OS_CryptoAgreement_Handle_t*   hAgree,
    const OS_Crypto_Handle_t       self,
    const OS_CryptoKey_Handle_t    hPrvKey,
    const OS_CryptoAgreement_Alg_t algorithm)
{
    seos_err_t err;

    PROXY_INIT(*hAgree, self);
    if ((err = PROXY_CALL(*hAgree, Agreement_init, PROXY_GET_PTR(*hAgree),
                          algorithm, PROXY_GET_OBJ(hPrvKey))) != SEOS_SUCCESS)
    {
        PROXY_FREE(*hAgree);
    }

    return err;
}

seos_err_t
OS_CryptoAgreement_free(
    OS_CryptoAgreement_Handle_t hAgree)
{
    seos_err_t err;

    err = PROXY_CALL(hAgree, Agreement_free, PROXY_GET_OBJ(hAgree));
    PROXY_FREE(hAgree);

    return err;
}

seos_err_t
OS_CryptoAgreement_agree(
    OS_CryptoAgreement_Handle_t hAgree,
    const OS_CryptoKey_Handle_t hPubKey,
    void*                       shared,
    size_t*                     sharedSize)
{
    return PROXY_CALL(hAgree, Agreement_agree, PROXY_GET_OBJ(hAgree),
                      PROXY_GET_OBJ(hPubKey), shared, sharedSize);
}