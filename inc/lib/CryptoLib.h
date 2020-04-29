/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file CryptoLib.h
 *
 * @brief Crypto library core module
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "Crypto_Impl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLib CryptoLib_t;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
CryptoLib_init(
    Crypto_Impl_t*            impl,
    const OS_Crypto_Memory_t* memory,
    const CryptoLib_Config_t* cfg);

seos_err_t
CryptoLib_free(
    CryptoLib_t* self);

/** @} */
