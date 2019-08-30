/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoRng.h
 *
 * @brief SEOS Crypto Random Number generator context and functions
 *
 */
#pragma once

#include "seos_err.h"
#include "seos_rng.h"

#include "LibDebug/Debug.h"

#include "compiler.h"

/**
 * @brief implementation beneath SeosCryptoRng_nextBytes
 */
typedef int (*SeosCryptoRng_ImplRngFunc)(void*, void*, size_t);

typedef struct
{
    SeosCryptoRng_ImplRngFunc rngFunc;
    void* implCtx;
}
SeosCryptoRng;

/**
 * @brief initializes an rng context
 *
 * @param self (required) pointer to context to initialize
 * @param imlp pointer to the implementation context that will be used by the
 * rngFunc
 * @param rngFunc function pointer to a SeosCryptoRng_ImplRngFunc
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 *
 */
seos_err_t
SeosCryptoRng_init(SeosCryptoRng* self,
                   void* impl,
                   SeosCryptoRng_ImplRngFunc rngFunc);
/**
 * @brief get random bytes
 *
 * @param self (required) pointer to context
 * @param destination (required) pointer to the destination buffer
 * @param destinationSize size of the destination buffer
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 *
 */
seos_err_t
SeosCryptoRng_nextBytes(SeosCryptoRng* self,
                        void* destination,
                        size_t destinationSize);
/**
 * @brief deinitializes an rng context
 *
 * @param self (required) pointer to context to initialize
 *
 */
void
SeosCryptoRng_deInit(SeosCryptoRng* self);

/** @} */
