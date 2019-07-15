/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup SEOS
 * @{
 *
 * @file SeosCryptoRng.c
 *
 */
#include "SeosCryptoRng.h"

#include <string.h>

seos_err_t
SeosCryptoRng_init(SeosCryptoRng* self,
                   void* impl,
                   SeosCryptoRng_ImplRngFunc rngFunc)
{
    Debug_ASSERT_SELF(self);

    seos_err_t retval = SEOS_SUCCESS;

    memset(self, 0, sizeof(*self));

    if (NULL == impl || NULL == rngFunc)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        self->implCtx = impl;
        self->rngFunc = rngFunc;
    }
    return retval;
}

seos_err_t
SeosCryptoRng_nextBytes(SeosCryptoRng* self,
                        void* destination,
                        size_t destinationSize)
{
    Debug_ASSERT_SELF(self);
    return self->rngFunc(self->implCtx, destination, destinationSize)
           ? SEOS_ERROR_GENERIC : SEOS_SUCCESS;
}

void
SeosCryptoRng_deInit(SeosCryptoRng* self)
{
    Debug_ASSERT_SELF(self);
    return;
}

/** @} */
