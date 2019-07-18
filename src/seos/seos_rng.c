/*
 *  SEOS Random Number Generator
 *
 *  Copyright (C) 2018, Hensoldt Cyber GmbH
 *
 *
 *  currently uses mbedTLS functuons
 *
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
#error "missing mbedTLS configuration"
#endif


#include <stdio.h>
#include <string.h>

#include "seos_rng.h"

//------------------------------------------------------------------------------
static int glue_mbedtls_entropy_func(
    void* ctx,
    unsigned char* output,
    size_t len
)
{
    Debug_LOG_TRACE( "%s(): buf %p, len = %d\n", __func__, output, len );

    // seos_rng_t *seos_rng = (seos_rng_t *)ctx;

    // there is an mbedTLS function
    //    int ret = mbedtls_entropy_func( &(seos_rng->entropy), output, len);
    // but in the end it also depends on having entropy sources, otherwise it
    // returns MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED

    // ToDo: we need an entropy source!
    memset( output, 0xA5, len );

    return 0;
}

//------------------------------------------------------------------------------
int seos_rng_init(
    seos_rng_t* seos_rng,
    const void* seed,
    size_t len
)
{
    mbedtls_entropy_init( &(seos_rng->entropy) );

    mbedtls_ctr_drbg_init( &(seos_rng->ctr_drbg) );

    int ret = mbedtls_ctr_drbg_seed(
                  &(seos_rng->ctr_drbg),
                  &glue_mbedtls_entropy_func,
                  seos_rng,
                  (const unsigned char*)seed,
                  len);
    if (ret != 0)
    {
        printf( "mbedtls_ctr_drbg_seed() returned %d\n", ret );
        seos_rng_free( seos_rng );
        return -1;
    }

    // https://tls.mbed.org/kb/how-to/add-a-random-generator
    // Enabling prediction resistance by gathering entropy before each call.
    // This is costly and requires ample supply of good entropy.
    //
    // mbedtls_ctr_drbg_set_prediction_resistance( &(seos_rng->ctr_drbg),
    //                                             MBEDTLS_CTR_DRBG_PR_ON );

    return 0;
}

//------------------------------------------------------------------------------
void seos_rng_free(
    seos_rng_t* seos_rng
)
{
    mbedtls_ctr_drbg_free( &(seos_rng->ctr_drbg) );
    mbedtls_entropy_free( &(seos_rng->entropy) );
}


//------------------------------------------------------------------------------
int seos_rng_get_prng_bytes(
    seos_rng_t* seos_rng,
    void* buffer,
    size_t len
)
{
    // for now this calls a mbedTLS function
    return mbedtls_ctr_drbg_random( &(seos_rng->ctr_drbg), buffer, len );
}


