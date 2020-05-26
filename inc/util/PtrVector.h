/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Error.h"
#include "LibUtil/PointerVector.h"

typedef PointerVector PtrVector;

size_t
PtrVector_find(
    PtrVector*  v,
    const void* obj);

bool
PtrVector_hasPtr(
    PtrVector*  v,
    const void* obj);

OS_Error_t
PtrVector_remove(
    PtrVector*  v,
    const void* obj);

OS_Error_t
PtrVector_add(
    PtrVector* v,
    void*      obj);

void
PtrVector_free(
    PtrVector* v);

OS_Error_t
PtrVector_init(
    PtrVector* v);