/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCrypto_Handles.h
 *
 * @brief SEOS Crypto handles definition
 *
 */

#include "SeosCryptoKey_Impl_v5.h"
#include "SeosCryptoDigest_Impl.h"
#include "SeosCryptoCipher_Impl.h"
#include "SeosCryptoAgreement_Impl.h"
#include "SeosCryptoSignature_Impl.h"

typedef SeosCryptoKey_v5*       SeosCrypto_KeyHandle_v5;
typedef SeosCryptoDigest*       SeosCrypto_DigestHandle;
typedef SeosCryptoCipher*       SeosCrypto_CipherHandle;
typedef SeosCryptoSignature*    SeosCrypto_SignatureHandle;
typedef SeosCryptoAgreement*    SeosCrypto_AgreementHandle;

/** @} */
