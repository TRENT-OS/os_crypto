/**
 * Copyright (C) 2019-2020, HENSOLDT Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Crypto.int.h"

#include "lib_macros/Check.h"

OS_Error_t
OS_CryptoRng_getBytes(
    OS_Crypto_Handle_t        hCrypto,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize)
{
    CHECK_PTR_NOT_NULL(hCrypto);

    return CALL(hCrypto, Rng_getBytes, flags, buf, bufSize);
}

OS_Error_t
OS_CryptoRng_reseed(
    OS_Crypto_Handle_t hCrypto,
    const void*        seed,
    const size_t       seedSize)
{
    CHECK_PTR_NOT_NULL(hCrypto);

    return CALL(hCrypto, Rng_reseed, seed, seedSize);
}