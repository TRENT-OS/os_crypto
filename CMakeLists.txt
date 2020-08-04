#
# OS Crypto Library
#
# Copyright (C) 2019-2020, Hensoldt Cyber GmbH
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
        "src/util/PtrVector.c"
        "src/rpc/CryptoLibClient.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_crypto
        os_core_api
        os_libs
)