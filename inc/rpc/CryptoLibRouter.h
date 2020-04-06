/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file CryptoLibRouter.h
 *
 * @brief The router instantiates the API as library AND RPC client and switches
 * between these contexts based on attributes of they key. This way, critical
 * operations will transparently be executed in an isolated component (e.g., the
 * CryptoServer) and uncritical operations will be performed locally and thus
 * faster.
 */

#pragma once

#include "OS_Crypto.h"

#include "Crypto_Impl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct CryptoLibRouter CryptoLibRouter_t;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
CryptoLibRouter_init(
    Crypto_Impl_t*                  impl,
    const OS_Crypto_Memory_t*       memIf,
    const CryptoLibRouter_Config_t* cfg);

seos_err_t
CryptoLibRouter_free(
    CryptoLibRouter_t* self);

/** @} */