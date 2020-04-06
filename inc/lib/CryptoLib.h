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

#include "lib/CryptoLibCipher.h"
#include "lib/CryptoLibKey.h"
#include "lib/CryptoLibRng.h"
#include "lib/CryptoLibDigest.h"
#include "lib/CryptoLibMac.h"
#include "lib/CryptoLibSignature.h"
#include "lib/CryptoLibAgreement.h"

#include "OS_CryptoImpl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLib CryptoLib_t;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
CryptoLib_init(
    OS_CryptoImpl_t*          impl,
    const OS_Crypto_Memory_t* memIf,
    const CryptoLib_Config_t* cfg);

seos_err_t
CryptoLib_free(
    CryptoLib_t* self);

/** @} */
