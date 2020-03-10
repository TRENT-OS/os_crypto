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

#include "util/PtrVector.h"
#include "lib/SeosCryptoLib_Rng.h"

// -------------------------- defines/types/variables --------------------------

typedef struct SeosCryptoLib SeosCryptoLib;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
SeosCryptoLib_init(
    SeosCryptoApi_Impl*             impl,
    const SeosCryptoApi_MemIf*      memIf,
    const SeosCryptoApi_Lib_Config* cfg);

seos_err_t
SeosCryptoLib_free(
    SeosCryptoLib* self);

/** @} */
