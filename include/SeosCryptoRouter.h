/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup RPC
 * @{
 *
 * @file SeosCryptoRouter.h
 *
 * @brief The router instantiates the API as library AND RPC client and switches
 * between these contexts based on attributes of they key. This way, critical
 * operations will transparently be executed in an isolated component (e.g., the
 * CryptoServer) and uncritical operations will be performed locally and thus
 * faster.
 */

#pragma once

#include "SeosCryptoApi.h"

#include "SeosCryptoImpl.h"

// -------------------------- defines/types/variables --------------------------

typedef struct SeosCryptoRouter SeosCryptoRouter;

// ------------------------------- Init/Free -----------------------------------

seos_err_t
SeosCryptoRouter_init(
    SeosCryptoImpl*                impl,
    const SeosCryptoApi_MemIf*     memIf,
    const SeosCryptoRouter_Config* cfg);

seos_err_t
SeosCryptoRouter_free(
    SeosCryptoRouter* self);

/** @} */