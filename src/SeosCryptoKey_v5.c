/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoKey_v5.h"
#include "SeosCryptoRng.h"

#include "LibDebug/Debug.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"

#include <string.h>

// Private static functions ----------------------------------------------------


// Public functions ------------------------------------------------------------

seos_err_t
SeosCryptoKey_generate_v5(SeosCryptoKey_v5*         self,
                          const SeosCrypto_MemIf*   memIf,
                          SeosCryptoRng*            rng,
                          const void*               keySpec,
                          const size_t              specSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_makePublic_v5(SeosCryptoKey_v5*               self,
                            const SeosCrypto_MemIf*         memIf,
                            SeosCryptoRng*                  rng,
                            const SeosCryptoKey_v5*         prvKey,
                            const SeosCryptoKey_Attribs*    attribs)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_import_v5(SeosCryptoKey_v5*          self,
                        const SeosCrypto_MemIf*    memIf,
                        const SeosCryptoKey_v5*    wrapKey,
                        const SeosCryptoKey_Data*  keyData)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_export_v5(SeosCryptoKey_v5*       self,
                        const SeosCryptoKey_v5* wrapKey,
                        SeosCryptoKey_Data*     keyData)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_getParams_v5(SeosCryptoKey_v5*    self,
                           void*                keyParams,
                           size_t*              paramSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_loadParams_v5(const SeosCryptoKey_Param type,
                            void*                     keyParams,
                            size_t*                   paramSize)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}

seos_err_t
SeosCryptoKey_free_v5(SeosCryptoKey_v5*        self,
                      const SeosCrypto_MemIf*  memIf)
{
    return SEOS_ERROR_NOT_SUPPORTED;
}
