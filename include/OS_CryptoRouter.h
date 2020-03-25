/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file OS_CryptoRouter.h
 *
 * @brief The router instantiates the API as library AND RPC client and switches
 * between these contexts based on attributes of they key. This way, critical
 * operations will transparently be executed in an isolated component (e.g., the
 * CryptoServer) and uncritical operations will be performed locally and thus
 * faster.
 */

#pragma once

#include "OS_Crypto.h"

#include "OS_CryptoImpl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct OS_CryptoRouter OS_CryptoRouter;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
OS_CryptoRouter_init(
    OS_CryptoImpl*                impl,
    const OS_Crypto_Memory*       memIf,
    const OS_CryptoRouter_Config* cfg);

seos_err_t
OS_CryptoRouter_free(
    OS_CryptoRouter* self);

/** @} */