/**
 * Copyright (C) 2019-2020, HENSOLDT Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#include "lib_macros/Check.h"

OS_Error_t
OS_CryptoAgreement_init(
    OS_CryptoAgreement_Handle_t*   self,
    const OS_Crypto_Handle_t       hCrypto,
    const OS_CryptoKey_Handle_t    hPrvKey,
    const OS_CryptoAgreement_Alg_t algorithm)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hCrypto);
    CHECK_PTR_NOT_NULL(hPrvKey);

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

    CHECK_PTR_NOT_NULL(self);

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
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(hPubKey);

    if (self->impl->context != hPubKey->impl->context
        || self->impl->vtable != hPubKey->impl->vtable)
    {
        Debug_LOG_ERROR("Given keys are not managed by the same library "
                        "instance, this may be because one is local and "
                        "the other in a remote component");
        return OS_ERROR_INVALID_PARAMETER;
    }

    return PROXY_CALL(self, Agreement_agree, PROXY_GET_OBJ(self),
                      PROXY_GET_OBJ(hPubKey), shared, sharedSize);
}