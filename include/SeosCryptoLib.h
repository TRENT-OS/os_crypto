/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Crypto
 * @{
 *
 * @file SeosCryptoLib.h
 *
 * @brief Crypto library core module
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "lib/SeosCryptoLib_Cipher.h"
#include "lib/SeosCryptoLib_Key.h"
#include "lib/SeosCryptoLib_Rng.h"
#include "lib/SeosCryptoLib_Digest.h"
#include "lib/SeosCryptoLib_Mac.h"
#include "lib/SeosCryptoLib_Signature.h"
#include "lib/SeosCryptoLib_Agreement.h"

// -------------------------- defines/types/variables --------------------------

typedef struct SeosCryptoLib SeosCryptoLib;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
SeosCryptoLib_init(
    SeosCryptoApi_Impl*         impl,
    const SeosCryptoApi_MemIf*  memIf,
    const SeosCryptoLib_Config* cfg);

seos_err_t
SeosCryptoLib_free(
    SeosCryptoLib* self);

/** @} */
