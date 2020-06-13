#
# OS Crypto Library
#
# Copyright (C) 2019-2020, Hensoldt Cyber GmbH
#
# We have three library targets:
# 1. OS_CRYPTO:
#    Provides only functionality of the crypto library behind calls to the API.
# 2. OS_CRYPTO_WITH_RPC_CLIENT:
#    Provides library functionality to execute crypto locally, but also allows
#    to operate crypto API in RPC client mode, where calls to the API are
#    transparently mapped to an RPC interface and executed in a separate component
#    (e.g., the CryptoServer)
# 3. OS_CRYPTO_WITH_RPC_SEVER:
#    Provides library functionality to execute crypto locally, but also allows
#    to instantiate the crypto API as RPC server easily, which can then be used
#    to serve RPC requests from a crypto API RPC client.
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)

# We need to build 3rdparty/mbedtls for this and would like to avoid
# all users of OS_CRYPTO to include this as well, so we do it here
os_use_libs(
    3RDPARTY_MBEDTLS_FOR_CRYPTO
)


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


#------------------------------------------------------------------------------
project(os_crypto_with_rpc_client C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/rpc/CryptoLibClient.c"
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
       OS_CRYPTO_WITH_RPC_CLIENT
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_crypto
)


#------------------------------------------------------------------------------
project(os_crypto_with_rpc_server C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/rpc/CryptoLibServer.c"
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
       OS_CRYPTO_WITH_RPC_SERVER
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_crypto
)


#------------------------------------------------------------------------------
# if invoked from the OS sandbox, provide a documentation build target
if (COMMAND os_create_doxygen_target)

    os_create_doxygen_target( os_crypto_doc
        # API header is documented as part of os_core_api, so we do nothing
        "echo"
        # API header is documented as part of os_core_api, so we do nothing
        "echo"
    )

endif()
