/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

#pragma once


typedef enum
{
    MBEDTLS_OK,             /**< Local constant to improve code readability using mbedtls */
    KEY_SIZE_NOT_SUPPORTED, /**< Wrond size of key */
    AES_CTR_FAIL,           /**< AES CTR failed to encrypt or decrypt buffer */
    AES_ECB_FAIL,           /**< AES ECB failed to encrypt or decrypt buffer */

    //----------------------------------------
    CRYPTO_SUCCESS
}
Crypto_Error_t;
