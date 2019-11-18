/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosCrypto_Handles.h
 *
 * @brief Crypto handles definition
 *
 */

#include "SeosCryptoKey_Impl.h"
#include "SeosCryptoDigest_Impl.h"
#include "SeosCryptoMac_Impl.h"
#include "SeosCryptoCipher_Impl.h"
#include "SeosCryptoAgreement_Impl.h"
#include "SeosCryptoSignature_Impl.h"

typedef SeosCryptoKey*          SeosCrypto_KeyHandle;
typedef SeosCryptoDigest*       SeosCrypto_DigestHandle;
typedef SeosCryptoMac*          SeosCrypto_MacHandle;
typedef SeosCryptoCipher*       SeosCrypto_CipherHandle;
typedef SeosCryptoSignature*    SeosCrypto_SignatureHandle;
typedef SeosCryptoAgreement*    SeosCrypto_AgreementHandle;

/** @} */
