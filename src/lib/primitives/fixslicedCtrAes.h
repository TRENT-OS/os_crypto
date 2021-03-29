/*
 * Copyright (C) 2021, Hensoldt Cyber GmbH
 */

#pragma once

#include "mbedtls/aes.h"

#include "OS_Error.h"
#include "OS_Crypto.h"

#define AES_CTR_COUNTER_SIZE 16

OS_Error_t trentos_aes_setkey_ctr(mbedtls_aes_context* aes, uint8_t* key,
                                  uint16_t key_size);

OS_Error_t trentos_aes_crypt_ctr(mbedtls_aes_context* aes,
                                 const uint8_t* input,
                                 uint8_t* output,
                                 const uint32_t input_length,
                                 uint8_t counter[AES_CTR_COUNTER_SIZE]);

