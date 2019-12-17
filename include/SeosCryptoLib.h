/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoLib.h
 *
 * @brief Crypto core functions
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "lib/SeosCryptoLib_Rng.h"

#include "LibUtil/PointerVector.h"

// Internal types/defines/enums ------------------------------------------------

#define SeosCryptoLib_SIZE_BUFFER SeosCryptoApi_SIZE_DATAPORT

typedef struct
{
    SeosCryptoApi_MemIf memIf;
    SeosCryptoLib_Rng cryptoRng;
    PointerVector keyHandleVector;
    PointerVector macHandleVector;
    PointerVector digestHandleVector;
    PointerVector cipherHandleVector;
    PointerVector signatureHandleVector;
    PointerVector agreementHandleVector;
    /**
     * When we have a function that takes an input buffer and produces an output
     * buffer, we copy the inputs to this buffer internally, so the caller can
     * use the identical buffer as input/output.
     */
    uint8_t buffer[SeosCryptoLib_SIZE_BUFFER];
} SeosCryptoLib;

// Internal functions ----------------------------------------------------------

seos_err_t
SeosCryptoLib_init(
    SeosCryptoLib*                  self,
    const SeosCryptoVtable**        vtable,
    const SeosCryptoApi_MemIf*      memIf,
    const SeosCryptoApi_Lib_Config* cfg);

seos_err_t
SeosCryptoLib_free(
    SeosCryptoLib* self);

/** @} */
