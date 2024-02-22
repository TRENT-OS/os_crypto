#
# OS Crypto
#
# Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#------------------------------------------------------------------------------
project(os_crypto C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_Crypto.c"
        "src/OS_CryptoAgreement.c"
        "src/OS_CryptoCipher.c"
        "src/OS_CryptoDigest.c"
        "src/OS_CryptoKey.c"
        "src/OS_CryptoMac.c"
        "src/OS_CryptoRng.c"
        "src/OS_CryptoSignature.c"
        "src/lib/CryptoLib.c"
        "src/lib/CryptoLibAgreement.c"
        "src/lib/CryptoLibRng.c"
        "src/lib/CryptoLibDigest.c"
        "src/lib/CryptoLibMac.c"
        "src/lib/CryptoLibCipher.c"
        "src/lib/CryptoLibSignature.c"
        "src/lib/CryptoLibKey.c"
        "src/lib/primitives/CryptoLibAes.c"
        "src/lib/primitives/CryptoLibAes.c"
        "src/rpc/CryptoLibClient.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_crypto
        lib_compiler
        lib_debug
        lib_macros
        os_core_api
)
