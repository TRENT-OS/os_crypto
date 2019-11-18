/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoMac.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private Functions -----------------------------------------------------------

// Public Functions ------------------------------------------------------------

seos_err_t
SeosCryptoMac_init(SeosCryptoMac*                 self,
                   const SeosCrypto_MemIf*        memIf,
                   const SeosCryptoMac_Algorithm  algorithm)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoMac_free(SeosCryptoMac*           self,
                   const SeosCrypto_MemIf*  memIf)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoMac_start(SeosCryptoMac*    self,
                    const void*       secret,
                    const size_t      secretSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoMac_process(SeosCryptoMac*    self,
                      const void*       data,
                      const size_t      dataSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoMac_finalize(SeosCryptoMac*   self,
                       void*            mac,
                       size_t*          macSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}