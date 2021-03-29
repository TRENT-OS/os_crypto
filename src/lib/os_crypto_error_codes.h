/*
 * Copyright (C) 2021, Hensoldt Cyber GmbH
 */

#pragma once

// Local constant to improve code readability using mbedtls
#define MBEDTLS_OK          0

// Bitsliced AES return codes
#define KEY_SIZE_NOT_SUPPORTED 2
#define BS_AES_CTR_SUCCESS  0
#define BS_AES_CTR_FAIL     1
