/*
 *  SEOS RNG
 *
 *  Copyright (C) 2018, Hensoldt Cyber GmbH
 */

#pragma once

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


typedef struct {
    mbedtls_entropy_context    entropy;
    mbedtls_ctr_drbg_context   ctr_drbg;
} seos_rng_t;


int seos_rng_init(
    seos_rng_t *seos_rng,
    const void *seed,
    size_t len);


void seos_rng_free(
    seos_rng_t *seos_rng);


int seos_rng_get_prng_bytes(
    seos_rng_t *seos_rng,
    void *buffer,
    size_t len);
