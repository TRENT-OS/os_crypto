/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 *
 * The plain C implementation is based on the paper at
 * https://eprint.iacr.org/2020/1123.pdf and its implementation by
 * Alexandre Adomnicai, Nanyang Technological University, Singapore
 * alexandre.adomnicai@ntu.edu.sg
 * October 2020
*/

#include <string.h>
#include "CryptoLibAes.h"


#if __ARM_FEATURE_CRYPTO == 1
#include <arm_neon.h>

void
neon_AesKeySchedule(uint8_t* round_keys,
                    uint8_t* key,
                    size_t key_size)
{
    uint8x16_t zero_key;
    zero_key = veorq_s8(zero_key, zero_key);

    uint8_t const rcon[] =
    {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    };
    uint32_t words_per_key_block = 4;
    memcpy(round_keys, key, AES_BLOCK_SIZE_IN_BYTE);
    for (size_t i = 0; i < sizeof(rcon); i++)
    {
        uint32_t* rki = round_keys + (i * words_per_key_block);
        uint32_t* rko = rki + words_per_key_block;
        uint32x4_t rki_32 = {rki[0], rki[1], rki[2], rki[3]};
        uint8x16_t rki_8 = vreinterpretq_u8_u32(rki_32);
        rki_8 = vaeseq_u8(rki_8, zero_key);
        rki_32 = vreinterpretq_u32_u8(rki_8);
        rko[0] = ror32_8(rki_32[3]) ^ rcon[i] ^ rki_32[0];
        rko[1] = rko[0] ^ rki_32[1];
        rko[2] = rko[1] ^ rki_32[2];
        rko[3] = rko[2] ^ rki_32[3];
        rki[0] = rki_32[0];
        rki[1] = rki_32[1];
        rki[2] = rki_32[2];
        rki[3] = rki_32[3];
        if (key_len == AES256_KEY_SIZE_IN_BITS)
        {
            if (i >= 6)
            {
                break;
            }
            rko[4] = aes_sub(rko[3]) ^ rki[4];
            rko[5] = rko[4] ^ rki[5];
            rko[6] = rko[5] ^ rki[6];
            rko[7] = rko[6] ^ rki[7];
        }
    }
}

void
neon_AesSingleBlock(uint8_t* ctext,
                    const uint8_t* ptext,
                    const uint32_t* round_keys,
                    uint32_t number_of_rounds)
{

    uint8x16_t data = vld1q_u8(ptext);

    for (i = 0; i < number_of_rounds - 1; ++i)
    {
        data = vaeseq_u8(data, round_keys[i]);
        data = vaesmcq_u8(data);
    }

    data = vaeseq_u8(data, round_keys[i++]);
    data = veorq_u8(data, round_keys[i]);

    vst1q_u8(ctext, data);
}

void
neon_AesDoubleBlock(unsigned char* ctext0,
                    unsigned char* ctext1,
                    const unsigned char* ptext0,
                    const unsigned char* ptext1,
                    const uint32_t* round_keys, uint32_t number_of_rounds)
{

    uint8x16_t data0 = vld1q_u8(ptext0);
    uint8x16_t data1 = vld1q_u8(ptext1);

    unsigned int i;
    for (i = 0; i < number_of_rounds - 1; ++i)
    {
        data0 = vaeseq_u8(data0, round_keys[i]);
        data0 = vaesmcq_u8(data0);

        data1 = vaeseq_u8(data1, round_keys[i]);
        data1 = vaesmcq_u8(data1);
    }

    data0 = vaeseq_u8(data0, round_keys[i]);
    data0 = veorq_u8(data0, round_keys[i + 1]);

    data1 = vaeseq_u8(data1, round_keys[i++]);
    data1 = veorq_u8(data1, round_keys[i]);

    vst1q_u8(ctext0, data0);
    vst1q_u8(ctext1, data1);
}

#else

// Private functions for plain C implementation

#define FS_AES128_RK_INT_SIZE 88
#define FS_AES256_RK_INT_SIZE 120

//Only used internally with shifts 8, 16 or 24.
static inline uint32_t
ror(uint32_t x,
    uint32_t y)
{
    return (x >> y) | (x << (32 - y));
}

static inline uint32_t
byte_ror_6(uint32_t x)
{
    return ((x >> 6) & 0x03030303) | ((x & 0x3f3f3f3f) << 2);
}

static inline uint32_t
byte_ror_4(uint32_t x)
{
    return ((x >> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4);
}

static inline uint32_t
byte_ror_2(uint32_t x)
{
    return ((x >> 2) & 0x3f3f3f3f) | ((x & 0x03030303) << 6);
}

static inline void
swapmove(uint32_t *a,
         uint32_t *b,
         int mask,
         int n)
{
    uint32_t tmp = (*b ^ (*a >> n)) & mask;
    *b ^= tmp;
    *a ^= (tmp << n);
}

static inline uint32_t
le_load_32(const uint8_t *x)
{
    return (((uint32_t) (x[3])) << 24) | (((uint32_t) (x[2])) << 16) |
           (((uint32_t) (x[1])) << 8) | ((uint32_t) x[0]);
}

static inline void
le_store_32(uint8_t *x,
            uint32_t y)
{
    x[0] = (uint8_t) (y & 0xff);
    x[1] = (uint8_t) ((y >> 8) & 0xff);
    x[2] = (uint8_t) ((y >> 16) & 0xff);
    x[3] = (uint8_t) ((y >> 24) & 0xff);
}

static void
inv_shiftrows_1(uint32_t* rkey)
{
    for (int i = 0; i < 8; i++)
    {
        swapmove(rkey + i, rkey + i, 0x0c0f0300, 4);
        swapmove(rkey + i, rkey + i, 0x33003300, 2);
    }
}

static void
inv_shiftrows_2(uint32_t* rkey)
{
    for (int i = 0; i < 8; i++)
    {
        swapmove(rkey + i, rkey + i, 0x0f000f00, 4);
    }
}

static void
inv_shiftrows_3(uint32_t* rkey)
{
    for (int i = 0; i < 8; i++)
    {
        swapmove(rkey + i, rkey + i, 0x030f0c00, 4);
        swapmove(rkey + i, rkey + i, 0x33003300, 2);
    }
}

static void
xor_columns(uint32_t* rkeys,
            int idx_xor,
            int idx_ror)
{
    rkeys[1] ^= 0xffffffff;             // NOT that are omitted in S-box
    rkeys[2] ^= 0xffffffff;             // NOT that are omitted in S-box
    rkeys[6] ^= 0xffffffff;             // NOT that are omitted in S-box
    rkeys[7] ^= 0xffffffff;             // NOT that are omitted in S-box
    for (int i = 0; i < 8; i++)
    {
        rkeys[i] = (rkeys[i - idx_xor] ^ ror(rkeys[i], idx_ror))  & 0xc0c0c0c0;
        rkeys[i] |= ((rkeys[i - idx_xor] ^ rkeys[i] >> 2) & 0x30303030);
        rkeys[i] |= ((rkeys[i - idx_xor] ^ rkeys[i] >> 2) & 0x0c0c0c0c);
        rkeys[i] |= ((rkeys[i - idx_xor] ^ rkeys[i] >> 2) & 0x03030303);
    }
}


void
packing(uint32_t* out,
        const uint8_t* in0,
        const uint8_t* in1)
{
    out[0] = le_load_32(in0);
    out[1] = le_load_32(in1);
    out[2] = le_load_32(in0 + 4);
    out[3] = le_load_32(in1 + 4);
    out[4] = le_load_32(in0 + 8);
    out[5] = le_load_32(in1 + 8);
    out[6] = le_load_32(in0 + 12);
    out[7] = le_load_32(in1 + 12);
    swapmove(out + 1, out, 0x55555555, 1);
    swapmove(out + 3, out + 2, 0x55555555, 1);
    swapmove(out + 5, out + 4, 0x55555555, 1);
    swapmove(out + 7, out + 6, 0x55555555, 1);
    swapmove(out + 2, out, 0x33333333, 2);
    swapmove(out + 3, out + 1, 0x33333333, 2);
    swapmove(out + 6, out + 4, 0x33333333, 2);
    swapmove(out + 7, out + 5, 0x33333333, 2);
    swapmove(out + 4, out, 0x0f0f0f0f, 4);
    swapmove(out + 5, out + 1, 0x0f0f0f0f, 4);
    swapmove(out + 6, out + 2, 0x0f0f0f0f, 4);
    swapmove(out + 7, out + 3, 0x0f0f0f0f, 4);
}

static void
unpacking(uint8_t* out0,
          uint8_t* out1,
          uint32_t* in)
{
    swapmove(in + 4, in, 0x0f0f0f0f, 4);
    swapmove(in + 5, in + 1, 0x0f0f0f0f, 4);
    swapmove(in + 6, in + 2, 0x0f0f0f0f, 4);
    swapmove(in + 7, in + 3, 0x0f0f0f0f, 4);
    swapmove(in + 2, in, 0x33333333, 2);
    swapmove(in + 3, in + 1, 0x33333333, 2);
    swapmove(in + 6, in + 4, 0x33333333, 2);
    swapmove(in + 7, in + 5, 0x33333333, 2);
    swapmove(in + 1, in, 0x55555555, 1);
    swapmove(in + 3, in + 2, 0x55555555, 1);
    swapmove(in + 5, in + 4, 0x55555555, 1);
    swapmove(in + 7, in + 6, 0x55555555, 1);
    le_store_32(out0, in[0]);
    le_store_32(out0 + 4, in[2]);
    le_store_32(out0 + 8, in[4]);
    le_store_32(out0 + 12, in[6]);
    le_store_32(out1, in[1]);
    le_store_32(out1 + 4, in[3]);
    le_store_32(out1 + 8, in[5]);
    le_store_32(out1 + 12, in[7]);
}

static void
add_round_key(uint32_t* state,
              const uint32_t* rkey)
{
    for (int i = 0; i < 8; i++)
    {
        state[i] ^= rkey[i];
    }
}

static void
double_shiftrows(uint32_t* state)
{
    for (int i = 0; i < 8; i++)
    {
        swapmove(state + i, state + i, 0x0f000f00, 4);
    }
}

static void
mixcolumns_0(uint32_t* state)
{
    uint32_t t0, t1, t2, t3, t4;
    t3 = ror(byte_ror_6(state[0]), 8);
    t0 = state[0] ^ t3;
    t1 = ror(byte_ror_6(state[7]), 8);
    t2 = state[7] ^ t1;
    state[7] = ror(byte_ror_4(t2), 16) ^ t1 ^ t0;
    t1 = ror(byte_ror_6(state[6]), 8);
    t4 = t1 ^ state[6];
    state[6] = t2 ^ t0 ^ t1 ^ ror(byte_ror_4(t4), 16);
    t1 = ror(byte_ror_6(state[5]), 8);
    t2 = t1 ^ state[5];
    state[5] = t4 ^ t1 ^ ror(byte_ror_4(t2), 16);
    t1 = ror(byte_ror_6(state[4]), 8);
    t4 = t1 ^ state[4];
    state[4] = t2 ^ t0 ^ t1 ^ ror(byte_ror_4(t4), 16);
    t1 = ror(byte_ror_6(state[3]), 8);
    t2 = t1 ^ state[3];
    state[3] = t4 ^ t0 ^ t1 ^ ror(byte_ror_4(t2), 16);
    t1 = ror(byte_ror_6(state[2]), 8);
    t4 = t1 ^ state[2];
    state[2] = t2 ^ t1 ^ ror(byte_ror_4(t4), 16);
    t1 = ror(byte_ror_6(state[1]), 8);
    t2 = t1 ^ state[1];
    state[1] = t4 ^ t1 ^ ror(byte_ror_4(t2), 16);
    state[0] = t2 ^ t3 ^ ror(byte_ror_4(t0), 16);
}

static void
mixcolumns_1(uint32_t* state)
{
    uint32_t t0, t1, t2;
    t0 = state[0] ^ ror(byte_ror_4(state[0]), 8);
    t1 = state[7] ^ ror(byte_ror_4(state[7]), 8);
    t2 = state[6];
    state[6] = t1 ^ t0;
    state[7] ^= state[6] ^ ror(t1, 16);
    t1 =  ror(byte_ror_4(t2), 8);
    state[6] ^= t1;
    t1 ^= t2;
    state[6] ^= ror(t1, 16);
    t2 = state[5];
    state[5] = t1;
    t1 =  ror(byte_ror_4(t2), 8);
    state[5] ^= t1;
    t1 ^= t2;
    state[5] ^= ror(t1, 16);
    t2 = state[4];
    state[4] = t1 ^ t0;
    t1 =  ror(byte_ror_4(t2), 8);
    state[4] ^= t1;
    t1 ^= t2;
    state[4] ^= ror(t1, 16);
    t2 = state[3];
    state[3] = t1 ^ t0;
    t1 =  ror(byte_ror_4(t2), 8);
    state[3] ^= t1;
    t1 ^= t2;
    state[3] ^= ror(t1, 16);
    t2 = state[2];
    state[2] = t1;
    t1 = ror(byte_ror_4(t2), 8);
    state[2] ^= t1;
    t1 ^= t2;
    state[2] ^= ror(t1, 16);
    t2 = state[1];
    state[1] = t1;
    t1 = ror(byte_ror_4(t2), 8);
    state[1] ^= t1;
    t1 ^= t2;
    state[1] ^= ror(t1, 16);
    t2 = state[0];
    state[0] = t1;
    t1 = ror(byte_ror_4(t2), 8);
    state[0] ^= t1;
    t1 ^= t2;
    state[0] ^= ror(t1, 16);
}

static void
mixcolumns_2(uint32_t* state)
{
    uint32_t t0, t1, t2, t3, t4;
    t3 = ror(byte_ror_2(state[0]), 8);
    t0 = state[0] ^ t3;
    t1 = ror(byte_ror_2(state[7]), 8);
    t2 = state[7] ^ t1;
    state[7] = ror(byte_ror_4(t2), 16) ^ t1 ^ t0;
    t1 = ror(byte_ror_2(state[6]), 8);
    t4 = t1 ^ state[6];
    state[6] = t2 ^ t0 ^ t1 ^ ror(byte_ror_4(t4), 16);
    t1 = ror(byte_ror_2(state[5]), 8);
    t2 = t1 ^ state[5];
    state[5] = t4 ^ t1 ^ ror(byte_ror_4(t2), 16);
    t1 = ror(byte_ror_2(state[4]), 8);
    t4 = t1 ^ state[4];
    state[4] = t2 ^ t0 ^ t1 ^ ror(byte_ror_4(t4), 16);
    t1 = ror(byte_ror_2(state[3]), 8);
    t2 = t1 ^ state[3];
    state[3] = t4 ^ t0 ^ t1 ^ ror(byte_ror_4(t2), 16);
    t1 = ror(byte_ror_2(state[2]), 8);
    t4 = t1 ^ state[2];
    state[2] = t2 ^ t1 ^ ror(byte_ror_4(t4), 16);
    t1 = ror(byte_ror_2(state[1]), 8);
    t2 = t1 ^ state[1];
    state[1] = t4 ^ t1 ^ ror(byte_ror_4(t2), 16);
    state[0] = t2 ^ t3 ^ ror(byte_ror_4(t0), 16);
}

static void
mixcolumns_3(uint32_t* state)
{
    uint32_t t0, t1, t2;
    t0 = state[7] ^ ror(state[7], 8);
    t2 = state[0] ^ ror(state[0], 8);
    state[7] = t2 ^ ror(state[7], 8) ^ ror(t0, 16);
    t1 = state[6] ^ ror(state[6], 8);
    state[6] = t0 ^ t2 ^ ror(state[6], 8) ^ ror(t1, 16);
    t0 = state[5] ^ ror(state[5], 8);
    state[5] = t1 ^ ror(state[5], 8) ^ ror(t0, 16);
    t1 = state[4] ^ ror(state[4], 8);
    state[4] = t0 ^ t2 ^ ror(state[4], 8) ^ ror(t1, 16);
    t0 = state[3] ^ ror(state[3], 8);
    state[3] = t1 ^ t2 ^ ror(state[3], 8) ^ ror(t0, 16);
    t1 = state[2] ^ ror(state[2], 8);
    state[2] = t0 ^ ror(state[2], 8) ^ ror(t1, 16);
    t0 = state[1] ^ ror(state[1], 8);
    state[1] = t1 ^ ror(state[1], 8) ^ ror(t0, 16);
    state[0] = t0 ^ ror(state[0], 8) ^ ror(t2, 16);
}

void
sbox(uint32_t* state)
{
    uint32_t t0, t1, t2, t3, t4, t5,
             t6, t7, t8, t9, t10, t11, t12,
             t13, t14, t15, t16, t17;
    t0          = state[3] ^ state[5];
    t1          = state[0] ^ state[6];
    t2          = t1 ^ t0;
    t3          = state[4] ^ t2;
    t4          = t3 ^ state[5];
    t5          = t2 & t4;
    t6          = t4 ^ state[7];
    t7          = t3 ^ state[1];
    t8          = state[0] ^ state[3];
    t9          = t7 ^ t8;
    t10         = t8 & t9;
    t11         = state[7] ^ t9;
    t12         = state[0] ^ state[5];
    t13         = state[1] ^ state[2];
    t14         = t4 ^ t13;
    t15         = t14 ^ t9;
    t16         = t0 & t15;
    t17         = t16 ^ t10;
    state[1]    = t14 ^ t12;
    state[2]    = t12 & t14;
    state[2]    ^= t10;
    state[4]    = t13 ^ t9;
    state[5]    = t1 ^ state[4];
    t3          = t1 & state[4];
    t10         = state[0] ^ state[4];
    t13         ^= state[7];
    state[3]    ^= t13;
    t16         = state[3] & state[7];
    t16         ^= t5;
    t16         ^= state[2];
    state[1]    ^= t16;
    state[0]    ^= t13;
    t16         = state[0] & t11;
    t16         ^= t3;
    state[2]    ^= t16;
    state[2]    ^= t10;
    state[6]    ^= t13;
    t10         = state[6] & t13;
    t3          ^= t10;
    t3          ^= t17;
    state[5]    ^= t3;
    t3          = state[6] ^ t12;
    t10         = t3 & t6;
    t5          ^= t10;
    t5          ^= t7;
    t5          ^= t17;
    t7          = t5 & state[5];
    t10         = state[2] ^ t7;
    t7          ^= state[1];
    t5          ^= state[1];
    t16         = t5 & t10;
    state[1]    ^= t16;
    t17         = state[1] & state[0];
    t11         = state[1] & t11;
    t16         = state[5] ^ state[2];
    t7          &= t16;
    t7          ^= state[2];
    t16         = t10 ^ t7;
    state[2]    &= t16;
    t10         ^= state[2];
    t10         &= state[1];
    t5          ^= t10;
    t10         = state[1] ^ t5;
    state[4]    &= t10;
    t11         ^= state[4];
    t1          &= t10;
    state[6]    &= t5;
    t10         = t5 & t13;
    state[4]    ^= t10;
    state[5]    ^= t7;
    state[2]    ^= state[5];
    state[5]    = t5 ^ state[2];
    t5          = state[5] & t14;
    t10         = state[5] & t12;
    t12         = t7 ^ state[2];
    t4          &= t12;
    t2          &= t12;
    t3          &= state[2];
    state[2]    &= t6;
    state[2]    ^= t4;
    t13         = state[4] ^ state[2];
    state[3]    &= t7;
    state[1]    ^= t7;
    state[5]    ^= state[1];
    t6          = state[5] & t15;
    state[4]    ^= t6;
    t0          &= state[5];
    state[5]    = state[1] & t9;
    state[5]    ^= state[4];
    state[1]    &= t8;
    t6          = state[1] ^ state[5];
    t0          ^= state[1];
    state[1]    = t3 ^ t0;
    t15         = state[1] ^ state[3];
    t2          ^= state[1];
    state[0]    = t2 ^ state[5];
    state[3]    = t2 ^ t13;
    state[1]    = state[3] ^ state[5];
    t0          ^= state[6];
    state[5]    = t7 & state[7];
    t14         = t4 ^ state[5];
    state[6]    = t1 ^ t14;
    state[6]    ^= t5;
    state[6]    ^= state[4];
    state[2]    = t17 ^ state[6];
    state[5]    = t15 ^ state[2];
    state[2]    ^= t6;
    state[2]    ^= t10;
    t14         ^= t11;
    t0          ^= t14;
    state[6]    ^= t0;
    state[7]    = t1 ^ t0;
    state[4]    = t14 ^ state[3];
}

void
aes128_keyschedule_ffs(uint32_t rkeys[FS_AES128_RK_INT_SIZE],
                       const uint8_t* key0,
                       const uint8_t* key1)
{
    packing(rkeys, key0, key1);     // packs the keys into the bitsliced state
    memcpy(rkeys + 8, rkeys, 32);
    sbox(rkeys + 8);
    rkeys[15] ^= 0x00000300;        // 1st rconst
    xor_columns(rkeys + 8, 8, 2);   // Rotword and XOR between the columns
    memcpy(rkeys + 16, rkeys + 8, 32);
    sbox(rkeys + 16);
    rkeys[22] ^= 0x00000300;        // 2nd rconst
    xor_columns(rkeys + 16, 8, 2);  // Rotword and XOR between the columns
    inv_shiftrows_1(rkeys + 8);     // to match fixslicing
    memcpy(rkeys + 24, rkeys + 16, 32);
    sbox(rkeys + 24);
    rkeys[29] ^= 0x00000300;        // 3rd rconst
    xor_columns(rkeys + 24, 8, 2);  // Rotword and XOR between the columns
    inv_shiftrows_2(rkeys + 16);    // to match fixslicing
    memcpy(rkeys + 32, rkeys + 24, 32);
    sbox(rkeys + 32);
    rkeys[36] ^= 0x00000300;        // 4th rconst
    xor_columns(rkeys + 32, 8, 2);  // Rotword and XOR between the columns
    inv_shiftrows_3(rkeys + 24);    // to match fixslicing
    memcpy(rkeys + 40, rkeys + 32, 32);
    sbox(rkeys + 40);
    rkeys[43] ^= 0x00000300;        // 5th rconst
    xor_columns(rkeys + 40, 8, 2);  // Rotword and XOR between the columns
    memcpy(rkeys + 48, rkeys + 40, 32);
    sbox(rkeys + 48);
    rkeys[50] ^= 0x00000300;        // 6th rconst
    xor_columns(rkeys + 48, 8, 2);  // Rotword and XOR between the columns
    inv_shiftrows_1(rkeys + 40);    // to match fixslicing
    memcpy(rkeys + 56, rkeys + 48, 32);
    sbox(rkeys + 56);
    rkeys[57] ^= 0x00000300;        // 7th rconst
    xor_columns(rkeys + 56, 8, 2);  // Rotword and XOR between the columns
    inv_shiftrows_2(rkeys + 48);    // to match fixslicing
    memcpy(rkeys + 64, rkeys + 56, 32);
    sbox(rkeys + 64);
    rkeys[64] ^= 0x00000300;        // 8th rconst
    xor_columns(rkeys + 64, 8, 2);  // Rotword and XOR between the columns
    inv_shiftrows_3(rkeys + 56);    // to match fixslicing
    memcpy(rkeys + 72, rkeys + 64, 32);
    sbox(rkeys + 72);
    rkeys[79] ^= 0x00000300;        // 9th rconst
    rkeys[78] ^= 0x00000300;        // 9th rconst
    rkeys[76] ^= 0x00000300;        // 9th rconst
    rkeys[75] ^= 0x00000300;        // 9th rconst
    xor_columns(rkeys + 72, 8, 2);  // Rotword and XOR between the columns
    memcpy(rkeys + 80, rkeys + 72, 32);
    sbox(rkeys + 80);
    rkeys[86] ^= 0x00000300;        // 10th rconst
    rkeys[85] ^= 0x00000300;        // 10th rconst
    rkeys[83] ^= 0x00000300;        // 10th rconst
    rkeys[82] ^= 0x00000300;        // 10th rconst
    xor_columns(rkeys + 80, 8, 2);  // Rotword and XOR between the columns
    inv_shiftrows_1(rkeys + 72);
    for (int i = 1; i < 11; i++)
    {
        rkeys[i * 8 + 1] ^= 0xffffffff;     // NOT to speed up SBox calculations
        rkeys[i * 8 + 2] ^= 0xffffffff;     // NOT to speed up SBox calculations
        rkeys[i * 8 + 6] ^= 0xffffffff;     // NOT to speed up SBox calculations
        rkeys[i * 8 + 7] ^= 0xffffffff;     // NOT to speed up SBox calculations
    }
}



void
aes256_keyschedule_ffs(uint32_t rkeys[FS_AES256_RK_INT_SIZE],
                       const unsigned char* key0,
                       const unsigned char* key1)
{
    packing(rkeys, key0, key1);         // packs the keys into the bitsliced state
    packing(rkeys + 8, key0 + 16,
            key1 + 16);                 // packs the keys into the bitsliced state
    memcpy(rkeys + 16, rkeys + 8, 32);
    sbox(rkeys + 16);
    rkeys[23] ^= 0x00000300;            // 1st rconst
    xor_columns(rkeys + 16, 16, 2);     // Rotword and XOR between the columns
    memcpy(rkeys + 24, rkeys + 16, 32);
    sbox(rkeys + 24);
    xor_columns(rkeys + 24, 16, 26);    // XOR between the columns
    inv_shiftrows_1(rkeys + 8);         // to match fixslicing
    memcpy(rkeys + 32, rkeys + 24, 32);
    sbox(rkeys + 32);
    rkeys[38] ^= 0x00000300;            // 2nd rconst
    xor_columns(rkeys + 32, 16, 2);     // Rotword and XOR between the columns
    inv_shiftrows_2(rkeys + 16);        // to match fixslicing
    memcpy(rkeys + 40, rkeys + 32, 32);
    sbox(rkeys + 40);
    xor_columns(rkeys + 40, 16, 26);    // XOR between the columns
    inv_shiftrows_3(rkeys + 24);        // to match fixslicing
    memcpy(rkeys + 48, rkeys + 40, 32);
    sbox(rkeys + 48);
    rkeys[53] ^= 0x00000300;            // 3rd rconst
    xor_columns(rkeys + 48, 16, 2);     // Rotword and XOR between the columns
    memcpy(rkeys + 56, rkeys + 48, 32);
    sbox(rkeys + 56);
    xor_columns(rkeys + 56, 16, 26);    // XOR between the columns
    inv_shiftrows_1(rkeys + 40);        // to match fixslicing
    memcpy(rkeys + 64, rkeys + 56, 32);
    sbox(rkeys + 64);
    rkeys[68] ^= 0x00000300;            // 4th rconst
    xor_columns(rkeys + 64, 16, 2);     // Rotword and XOR between the columns
    inv_shiftrows_2(rkeys + 48);        // to match fixslicing
    memcpy(rkeys + 72, rkeys + 64, 32);
    sbox(rkeys + 72);
    xor_columns(rkeys + 72, 16, 26);    // XOR between the columns
    inv_shiftrows_3(rkeys + 56);        // to match fixslicing
    memcpy(rkeys + 80, rkeys + 72, 32);
    sbox(rkeys + 80);
    rkeys[83] ^= 0x00000300;            // 5th rconst
    xor_columns(rkeys + 80, 16, 2);     // Rotword and XOR between the columns
    memcpy(rkeys + 88, rkeys + 80, 32);
    sbox(rkeys + 88);
    xor_columns(rkeys + 88, 16, 26);    // XOR between the columns
    inv_shiftrows_1(rkeys + 72);        // to match fixslicing
    memcpy(rkeys + 96, rkeys + 88, 32);
    sbox(rkeys + 96);
    rkeys[98] ^= 0x00000300;            // 6th rconst
    xor_columns(rkeys + 96, 16, 2);     // Rotword and XOR between the columns
    inv_shiftrows_2(rkeys + 80);        // to match fixslicing
    memcpy(rkeys + 104, rkeys + 96, 32);
    sbox(rkeys + 104);
    xor_columns(rkeys + 104, 16, 26);   // XOR between the columns
    inv_shiftrows_3(rkeys + 88);        // to match fixslicing
    memcpy(rkeys + 112, rkeys + 104, 32);
    sbox(rkeys + 112);
    rkeys[113] ^= 0x00000300;           // 7th rconst
    xor_columns(rkeys + 112, 16, 2);    // Rotword and XOR between the columns
    inv_shiftrows_1(rkeys + 104);       // to match fixslicing
    for (int i = 1; i < 15; i++)
    {
        rkeys[i * 8 + 1] ^= 0xffffffff; // NOT to speed up SBox calculations
        rkeys[i * 8 + 2] ^= 0xffffffff; // NOT to speed up SBox calculations
        rkeys[i * 8 + 6] ^= 0xffffffff; // NOT to speed up SBox calculations
        rkeys[i * 8 + 7] ^= 0xffffffff; // NOT to speed up SBox calculations
    }
}

/******************************************************************************
* Fully-fixsliced AES-128 encryption (the ShiftRows is completely omitted).
* Two 128-bit blocks ptext0, ptext1 are encrypted into ctext0, ctext1 in ECB.
* The round keys are assumed to be pre-computed.
* Note that it can be included in serial operating modes since ptext0, ptext1
* can refer to the same block. Moreover ctext parameters can be the same as
* ptext parameters.
******************************************************************************/

void
aes128_encrypt_ffs(unsigned char* ctext0,
                   unsigned char* ctext1,
                   const unsigned char* ptext0,
                   const unsigned char* ptext1,
                   const uint32_t* rkeys_ffs)
{
    uint32_t state[8];                     // 256-bit internal state
    packing(state, ptext0, ptext1);        // packs into bitsliced representation
    add_round_key(state, rkeys_ffs);       // key whitening
    sbox(state);                           // 1st round
    mixcolumns_0(state);                   // 1st round
    add_round_key(state, rkeys_ffs + 8);   // 1st round
    sbox(state);                           // 2nd round
    mixcolumns_1(state);                   // 2nd round
    add_round_key(state, rkeys_ffs + 16);  // 2nd round
    sbox(state);                           // 3rd round
    mixcolumns_2(state);                   // 3rd round
    add_round_key(state, rkeys_ffs + 24);  // 3rd round
    sbox(state);                           // 4th round
    mixcolumns_3(state);                   // 4th round
    add_round_key(state, rkeys_ffs + 32);  // 4th round
    sbox(state);                           // 5th round
    mixcolumns_0(state);                   // 5th round
    add_round_key(state, rkeys_ffs + 40);  // 5th round
    sbox(state);                           // 6th round
    mixcolumns_1(state);                   // 6th round
    add_round_key(state, rkeys_ffs + 48);  // 6th round
    sbox(state);                           // 7th round
    mixcolumns_2(state);                   // 7th round
    add_round_key(state, rkeys_ffs + 56);  // 7th round
    sbox(state);                           // 8th round
    mixcolumns_3(state);                   // 8th round
    add_round_key(state, rkeys_ffs + 64);  // 8th round
    sbox(state);                           // 9th round
    mixcolumns_0(state);                   // 9th round
    add_round_key(state, rkeys_ffs + 72);  // 9th round
    sbox(state);                           // 10th round
    double_shiftrows(state);               // 10th round (resynchronization)
    add_round_key(state, rkeys_ffs + 80);  // 10th round
    unpacking(ctext0, ctext1, state);      // unpacks the state to the output
}

/******************************************************************************
* Fully-fixsliced AES-256 encryption (the ShiftRows is completely omitted).
* Two 128-bit blocks ptext0, ptext1 are encrypted into ctext0, ctext1 in ECB.
* The round keys are assumed to be pre-computed.
* Note that it can be included in serial operating modes since ptext0, ptext1
* can refer to the same block. Moreover ctext parameters can be the same as
* ptext parameters.
******************************************************************************/

void
aes256_encrypt_ffs(unsigned char* ctext0,
                   unsigned char* ctext1,
                   const unsigned char* ptext0,
                   const unsigned char* ptext1,
                   const uint32_t* rkeys_ffs)
{
    uint32_t state[8];                  // 256-bit internal state
    packing(state, ptext0, ptext1);     // packs into bitsliced representation
    for (int i = 0; i < 96; i += 32)    // loop over quadruple rounds
    {
        add_round_key(state, rkeys_ffs + i);
        sbox(state);
        mixcolumns_0(state);
        add_round_key(state, rkeys_ffs + i + 8);
        sbox(state);
        mixcolumns_1(state);
        add_round_key(state, rkeys_ffs + i + 16);
        sbox(state);
        mixcolumns_2(state);
        add_round_key(state, rkeys_ffs + i + 24);
        sbox(state);
        mixcolumns_3(state);
    }
    add_round_key(state, rkeys_ffs + 96);
    sbox(state);
    mixcolumns_0(state);
    add_round_key(state, rkeys_ffs + 104);
    sbox(state);
    double_shiftrows(state);            // resynchronization
    add_round_key(state, rkeys_ffs + 112);
    unpacking(ctext0, ctext1, state);   // unpacks the state to the output
}
#endif

// ECB modes for one or double block

OS_Error_t
CryptoLib_AesKeySchedule(mbedtls_aes_context* aes,
                         uint8_t* key,
                         size_t key_size)
{
    if (key_size != 128 && key_size != 256)
    {
        return CRYPTO_ERROR_KEY_SIZE_NOT_SUPPORTED;
    }
    aes->rk = aes->buf;
#if __ARM_FEATURE_CRYPTO == 1
    neon_AesKeySchedule(aes.rk, key, key_size);
    aes->nr = key_size == 128 ? AES128_NUMBER_OF_ROUNDS :
              AES256_NUMBER_OF_ROUNDS;
#else
    if (key_size == 128)
    {
        aes128_keyschedule_ffs(aes->rk, key, key);
    }
    else if (key_size == 256)
    {
        aes256_keyschedule_ffs(aes->rk, key, key);
    }
#endif
    return OS_SUCCESS;
}

OS_Error_t
CryptoLib_AesSingleBlock(uint8_t out[AES_BLOCK_SIZE_IN_BYTE],
                             const uint8_t in[AES_BLOCK_SIZE_IN_BYTE],
                             const uint32_t* round_keys,
                             const size_t number_of_rounds)
{
    if (number_of_rounds != AES128_NUMBER_OF_ROUNDS
        && number_of_rounds != AES256_NUMBER_OF_ROUNDS)
    {
        return CRYPTO_ERROR_KEY_SIZE_NOT_SUPPORTED;
    }
#if __ARM_FEATURE_CRYPTO == 1
    neon_AesSingleBlock(out, in, round_keys, number_of_rounds);
#else
    if (number_of_rounds == AES128_NUMBER_OF_ROUNDS)
    {
        aes128_encrypt_ffs(out, out, in, in, round_keys);
    }
    else if (number_of_rounds == AES256_NUMBER_OF_ROUNDS)
    {
        aes256_encrypt_ffs(out, out, in, in, round_keys);
    }
#endif
    return OS_SUCCESS;
}

OS_Error_t
CryptoLib_AesDoubleBlock(uint8_t out[2 * AES_BLOCK_SIZE_IN_BYTE],
                         uint8_t in[2 * AES_BLOCK_SIZE_IN_BYTE],
                         uint32_t* round_keys, size_t number_of_rounds)
{

    if (number_of_rounds != AES128_NUMBER_OF_ROUNDS
        && number_of_rounds != AES256_NUMBER_OF_ROUNDS)
    {
        return CRYPTO_ERROR_KEY_SIZE_NOT_SUPPORTED;
    }
#if __ARM_FEATURE_CRYPTO == 1
    neon_AesDoubleBlock(out, out + AES_BLOCK_SIZE_IN_BYTE,
                        in, in + AES_BLOCK_SIZE_IN_BYTE,
                        round_keys, number_of_rounds);
#else
    if (number_of_rounds == AES128_NUMBER_OF_ROUNDS)
    {
        aes128_encrypt_ffs(out, out + AES_BLOCK_SIZE_IN_BYTE,
                           in, in + AES_BLOCK_SIZE_IN_BYTE,
                           round_keys);
    }
    else if (number_of_rounds == AES256_NUMBER_OF_ROUNDS)
    {
        aes256_encrypt_ffs(out, out + AES_BLOCK_SIZE_IN_BYTE,
                           in, in + AES_BLOCK_SIZE_IN_BYTE,
                           round_keys);
    }
#endif
    return OS_SUCCESS;
}

// Helper functions for CTR mode

static void
increase_single_counter(uint8_t counter[AES_CTR_COUNTER_SIZE])
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

static void
increase_parallel_counters(uint8_t counter[2 * AES_CTR_COUNTER_SIZE])
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


// Public API of supported AES modes

OS_Error_t
CryptoLib_AesCryptEcb(mbedtls_aes_context* ctx,
                      const unsigned char input[16],
                      unsigned char output[16])
{
    return CryptoLib_AesSingleBlock(output, input, ctx->rk, ctx->nr);
}

OS_Error_t
CryptoLib_AesCryptCTR(mbedtls_aes_context* aes,
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
        if (CryptoLib_AesDoubleBlock(key_stream, double_counter, aes->rk, 
                                    aes->nr) != OS_SUCCESS){
            return AES_CTR_FAIL;
        }

        for (int i = 0; i < 2 * AES_CTR_COUNTER_SIZE; i++)
        {
            output[i + encrypted_bytes] = input[i + encrypted_bytes] 
                                            ^ key_stream[i];
        }

        increase_parallel_counters(double_counter);
        encrypted_bytes += 2 * AES_CTR_COUNTER_SIZE;
    }

    if (encrypted_bytes != input_length)
    {
        OS_Error_t return_value = OS_SUCCESS;
        if (input_length - encrypted_bytes > AES_BLOCK_SIZE_IN_BYTE){
            return_value = CryptoLib_AesDoubleBlock(key_stream, double_counter,
                                                    aes->rk, aes->nr);
        }else {
            return_value = CryptoLib_AesSingleBlock(key_stream, double_counter,
                                                    aes->rk, aes->nr);
        }
        
        if (return_value != OS_SUCCESS){
            return AES_CTR_FAIL;
        }

        for (int i = 0; i < input_length - encrypted_bytes; i++)
        {
            output[i + encrypted_bytes] = input[i + encrypted_bytes] 
                                            ^ key_stream[i];
        }
    }

    return OS_SUCCESS;
}
