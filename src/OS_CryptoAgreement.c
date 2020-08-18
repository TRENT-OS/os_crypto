/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

OS_Error_t
OS_CryptoAgreement_init(
    OS_CryptoAgreement_Handle_t*   self,
    const OS_Crypto_Handle_t       hCrypto,
    const OS_CryptoKey_Handle_t    hPrvKey,
    const OS_CryptoAgreement_Alg_t algorithm)
{
    OS_Error_t err;

    // We are actually not using this; lets check it anyways for consistency.
    if (NULL == hCrypto || NULL == hPrvKey)
    {
        return OS_ERROR_INVALID_HANDLE;
    }

    PROXY_INIT_FROM_KEY(*self, hPrvKey);
    if ((err = PROXY_CALL(*self, Agreement_init, PROXY_GET_OBJ_PTR(*self),
                          PROXY_GET_OBJ(hPrvKey), algorithm)) != OS_SUCCESS)
    {
        PROXY_FREE(*self);
    }

    return err;
}

OS_Error_t
OS_CryptoAgreement_free(
    OS_CryptoAgreement_Handle_t self)
{
    OS_Error_t err;

    err = PROXY_CALL(self, Agreement_free, PROXY_GET_OBJ(self));
    PROXY_FREE(self);

    return err;
}

OS_Error_t
OS_CryptoAgreement_agree(
    OS_CryptoAgreement_Handle_t self,
    const OS_CryptoKey_Handle_t hPubKey,
    void*                       shared,
    size_t*                     sharedSize)
{
    if (NULL == self || NULL == hPubKey)
    {
        return OS_ERROR_INVALID_HANDLE;
    }

    // Make sure public key is where the agreement object is by checking that
    // they are either both local or both in the client instance
    if (self->impl->context != hPubKey->impl->context
        || self->impl->vtable != hPubKey->impl->vtable)
    {
        return OS_ERROR_INVALID_HANDLE;
    }

    return PROXY_CALL(self, Agreement_agree, PROXY_GET_OBJ(self),
                      PROXY_GET_OBJ(hPubKey), shared, sharedSize);
}