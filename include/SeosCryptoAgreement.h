/**
 * Copyright(C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Wrappers
 * @{
 *
 * @file SeosCryptoAgreement.h
 *
 * @brief Agreement functions
 *
 */

#pragma once

#include "SeosCrypto_Impl.h"
#include "SeosCryptoRng_Impl.h"
#include "SeosCryptoAgreement_Impl.h"

#include "compiler.h"
#include "seos_err.h"

seos_err_t
SeosCryptoAgreement_init(SeosCryptoAgreement*                   self,
                         const SeosCrypto_MemIf*                memIf,
                         const SeosCryptoAgreement_Algorithm    algorithm,
                         const SeosCryptoKey*                   privateKey);

seos_err_t
SeosCryptoAgreement_agree(SeosCryptoAgreement*  self,
                          SeosCryptoRng*        rng,
                          const SeosCryptoKey*  pubKey,
                          void*                 shared,
                          size_t*               sharedSize);

seos_err_t
SeosCryptoAgreement_free(SeosCryptoAgreement*       self,
                         const SeosCrypto_MemIf*    memIf);

/** @} */
