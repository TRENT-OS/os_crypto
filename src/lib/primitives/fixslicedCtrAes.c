/*
 * Copyright (C) 2021, Hensoldt Cyber GmbH
 */

#include "fixslicedCtrAes.h"
#include "fixslicedAes.h"
#include <stdio.h>

#include "lib_compiler/compiler.h"

#include "lib_macros/Check.h"

#include "../os_crypto_error_codes.h"


//Private functions

static void increase_single_counter(uint8_t counter[AES_CTR_COUNTER_SIZE])
{

    counter[AES_CTR_COUNTER_SIZE - 1]++;
    // Test if counter[AES_CTR_COUNTER_SIZE - 1] is 0 without branching
    uint8_t carry = (uint8_t) ( ~counter[AES_CTR_COUNTER_SIZE - 1]
                                & ( counter[AES_CTR_COUNTER_SIZE - 1] + ~0 )) >> 7;

    // Propagate the carry
    for (size_t i = AES_CTR_COUNTER_SIZE - 2; i > 0; i--)
    {
        counter[i] += carry;
        carry = (uint8_t) ( ~counter[i] & ( counter[i] + ~0 )) >> 7;
    }
    counter[0] += carry;
}

static void increase_parallel_counters(uint8_t counter[2 *
                                                         AES_CTR_COUNTER_SIZE])
{

    counter[AES_CTR_COUNTER_SIZE - 1] += 1;
    counter[2 * AES_CTR_COUNTER_SIZE - 1] += 1;
    // Test if there is a carry without branching
    uint8_t carry0 = (uint8_t) ( ~counter[AES_CTR_COUNTER_SIZE - 1]
                                 & ( counter[AES_CTR_COUNTER_SIZE - 1] + ~0 )) >> 7;
    uint8_t carry1 = (uint8_t) ( ~counter[2 * AES_CTR_COUNTER_SIZE - 1]
                                 & ( counter[2 * AES_CTR_COUNTER_SIZE - 1] + ~0 )) >> 7;

    counter[AES_CTR_COUNTER_SIZE - 1] += 1;
    counter[2 * AES_CTR_COUNTER_SIZE - 1] += 1;
    // Test if there is a carry without branching
    carry0 |= (uint8_t) ( ~counter[AES_CTR_COUNTER_SIZE - 1]
                          & ( counter[AES_CTR_COUNTER_SIZE - 1] + ~0 )) >> 7;
    carry1 |= (uint8_t) ( ~counter[2 * AES_CTR_COUNTER_SIZE - 1]
                          & ( counter[2 * AES_CTR_COUNTER_SIZE - 1] + ~0 )) >> 7;

    // Propagate the carry
    for (size_t i = AES_CTR_COUNTER_SIZE - 2; i > 0; i--)
    {
        counter[i] += carry0;
        carry0 = (uint8_t) ( ~counter[i] & ( counter[i] + ~0 )) >> 7;

        counter[i + AES_CTR_COUNTER_SIZE] += carry1;
        carry1 = (uint8_t) ( ~counter[i + AES_CTR_COUNTER_SIZE]
                             & ( counter[i + AES_CTR_COUNTER_SIZE] + ~0 )) >> 7;
    }
    counter[0] += carry0;
    counter[AES_CTR_COUNTER_SIZE] += carry1;
}

//Public functions

OS_Error_t trentos_aes_setkey_ctr(mbedtls_aes_context* aes, uint8_t* key,
                                  uint16_t key_size)
{
    CHECK_PTR_NOT_NULL(aes);
    CHECK_PTR_NOT_NULL(key);

    if (key_size == 128)
    {

        uint32_t rk[88];
        aes128_keyschedule_ffs(rk, key, key);
        memset(aes->buf, 0, sizeof(aes->buf));
        for (size_t i = 0; i < 88; i++)
        {
            aes->buf[i] = rk[i];
        }

        aes->rk = aes->buf;
        aes->nr = 10;

        //zeroize the temporary buffer
        for (size_t i = 0; i < 88; i++)
        {
            *(volatile uint32_t*) &rk[i] = 0;
        }

        return BS_AES_CTR_SUCCESS;

    }
    else if (key_size == 256)
    {

        uint32_t rk[120];
        aes256_keyschedule_ffs(rk, key, key);
        memset(aes->buf, 0, sizeof(aes->buf));

        for (size_t i = 0; i < 120; i++)
        {
            aes->buf[i] = rk[i];
        }

        //zeroize the temporary buffer
        for (size_t i = 0; i < 120; i++)
        {
            *(volatile uint32_t*) &rk[i] = 0;
        }

        aes->rk = aes->buf;
        aes->nr = 14;

        return BS_AES_CTR_SUCCESS;
    }
    else
    {
        return KEY_SIZE_NOT_SUPPORTED;
    }
}

OS_Error_t trentos_aes_crypt_ctr(mbedtls_aes_context* aes,
                                 const uint8_t* input,
                                 uint8_t* output,
                                 const uint32_t input_length,
                                 uint8_t counter[AES_CTR_COUNTER_SIZE])
{

    uint32_t encrypted_bytes = 0;
    uint8_t double_counter[2 * AES_CTR_COUNTER_SIZE];
    memcpy(double_counter, counter, AES_CTR_COUNTER_SIZE);
    memcpy(double_counter + AES_CTR_COUNTER_SIZE,
           counter, AES_CTR_COUNTER_SIZE);
    increase_single_counter(double_counter + AES_CTR_COUNTER_SIZE);

    uint8_t key_stream[AES_CTR_COUNTER_SIZE * 2];

    while (encrypted_bytes <= input_length - 2 * AES_CTR_COUNTER_SIZE)
    {
        if (aes->nr == 10) //AES 128
        {
            aes128_encrypt_ffs(key_stream, key_stream + AES_CTR_COUNTER_SIZE,
                               double_counter,
                               double_counter + AES_CTR_COUNTER_SIZE, aes->rk);
        }
        if (aes->nr == 14) //AES 256
        {
            aes256_encrypt_ffs(key_stream, key_stream + AES_CTR_COUNTER_SIZE,
                               double_counter,
                               double_counter + AES_CTR_COUNTER_SIZE, aes->rk);
        }

        for (uint32_t i = 0; i < 2 * AES_CTR_COUNTER_SIZE; i++)
        {
            output[i + encrypted_bytes] = input[i + encrypted_bytes] ^ key_stream[i];
        }

        increase_parallel_counters(double_counter);
        encrypted_bytes += 2 * AES_CTR_COUNTER_SIZE;
    }

    if (encrypted_bytes != input_length)
    {

        if (aes->nr == 10) //AES 128
        {
            aes128_encrypt_ffs(key_stream, key_stream + AES_CTR_COUNTER_SIZE,
                               double_counter,
                               double_counter + AES_CTR_COUNTER_SIZE, aes->rk);
        }
        if (aes->nr == 14) //AES 256
        {
            aes256_encrypt_ffs(key_stream, key_stream + AES_CTR_COUNTER_SIZE,
                               double_counter,
                               double_counter + AES_CTR_COUNTER_SIZE, aes->rk);
        }
        for (uint32_t i = 0; i < input_length - encrypted_bytes; i++)
        {
            output[i + encrypted_bytes] = input[i + encrypted_bytes] ^ key_stream[i];
        }
    }

    return OS_SUCCESS;
}