/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file OS_CryptoLib.h
 *
 * @brief Crypto library core module
 *
 */

#pragma once

#include "OS_Crypto.h"

#include "lib/OS_CryptoLibCipher.h"
#include "lib/OS_CryptoLibKey.h"
#include "lib/OS_CryptoLibRng.h"
#include "lib/OS_CryptoLibDigest.h"
#include "lib/OS_CryptoLibMac.h"
#include "lib/OS_CryptoLibSignature.h"
#include "lib/OS_CryptoLibAgreement.h"

#include "OS_CryptoImpl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct OS_CryptoLib OS_CryptoLib_t;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
OS_CryptoLib_init(
    OS_CryptoImpl_t*             impl,
    const OS_Crypto_Memory_t*    memIf,
    const OS_CryptoLib_Config_t* cfg);

seos_err_t
OS_CryptoLib_free(
    OS_CryptoLib_t* self);

/** @} */
