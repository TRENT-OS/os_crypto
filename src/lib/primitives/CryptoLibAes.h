/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 *
 * The plain C implementation is based on the paper at
 * https://eprint.iacr.org/2020/1123.pdf and its implementation by
 * Alexandre Adomnicai, Nanyang Technological University, Singapore
 *			alexandre.adomnicai@ntu.edu.sg
 *
 *
 * The optimized implementation is based on ARM NEON AES instructions.
 */


#pragma once

#include <stdint.h>
#include "mbedtls/aes.h"
#include "OS_Error.h"

#define AES_BLOCK_SIZE_IN_BYTE 16
#define AES_CTR_COUNTER_SIZE 16


#define AES128_KEY_SIZE_IN_BITS 128
#define AES128_KEY_SIZE_IN_BYTES 16
#define AES128_NUMBER_OF_ROUNDS  10

#define AES256_KEY_SIZE_IN_BITS 256
#define AES256_KEY_SIZE_IN_BYTES 32
#define AES256_NUMBER_OF_ROUNDS  14


OS_Error_t CryptoLib_AesKeySchedule(mbedtls_aes_context* aes,
                                    uint8_t* key,
                                    size_t key_size);

OS_Error_t CryptoLib_AesCryptEcb(mbedtls_aes_context* ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16]);

OS_Error_t CryptoLib_AesCryptCTR(mbedtls_aes_context* aes,
                                 const uint8_t* input,
                                 uint8_t* output,
                                 const uint32_t input_length,
                                 uint8_t counter[AES_CTR_COUNTER_SIZE]);
