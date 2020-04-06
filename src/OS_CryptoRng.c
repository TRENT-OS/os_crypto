/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "OS_Crypto_Object.h"

#include "lib/CryptoLibRng.h"

seos_err_t
OS_CryptoRng_getBytes(
    OS_Crypto_Handle_t        self,
    const OS_CryptoRng_Flag_t flags,
    void*                     buf,
    const size_t              bufSize)
{
    return CALL(self, Rng_getBytes, flags, buf, bufSize);
}

seos_err_t
OS_CryptoRng_reseed(
    OS_Crypto_Handle_t self,
    const void*        seed,
    const size_t       seedSize)
{
    return CALL(self, Rng_reseed, seed, seedSize);
}