#
# SEOS Crypto Library
#
# We have three library targets:
# 1. SEOS_CRYPTO:
#    Provides only functionality of the crypto library behind calls to the API.
# 2. SEOS_CRYPTO_WITH_RPC_CLIENT:
#    Provides library functionality to execute crypto locally, but also allows
#    to operate crypto API in RPC client mode, where calls to the API are
#    transparently mapped to an RPC interface and executed in a separate component
#    (e.g., the CryptoServer)
# 3. SEOS_CRYPTO_WITH_RPC_SEVER:
#    Provides library functionality to execute crypto locally, but also allows
#    to instantiate the crypto API as RPC server easily, which can then be used
#    to serve RPC requests from a crypto API RPC client.
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#------------------------------------------------------------------------------
project(seos_crypto_impl_mbedtls C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        # UTILS ----------------------------------------------------------------
        "3rdParty/mbedtls/library/platform_util.c"
        "3rdParty/mbedtls/library/bignum.c"
        # DIGEST ---------------------------------------------------------------
        "3rdParty/mbedtls/library/md.c"
        "3rdParty/mbedtls/library/md_wrap.c"
        "3rdParty/mbedtls/library/md5.c"
        "3rdParty/mbedtls/library/sha1.c"
        "3rdParty/mbedtls/library/sha256.c"
        # RNG ------------------------------------------------------------------
        "3rdParty/mbedtls/library/ctr_drbg.c"
        # CIPHER ---------------------------------------------------------------
        "3rdParty/mbedtls/library/cipher.c"
        "3rdParty/mbedtls/library/cipher_wrap.c"
        "3rdParty/mbedtls/library/aes.c"
        "3rdParty/mbedtls/library/gcm.c"
        # AGREEMENT ------------------------------------------------------------
        "3rdParty/mbedtls/library/dhm.c"
        "3rdParty/mbedtls/library/ecdh.c"
        "3rdParty/mbedtls/library/ecp.c"
        "3rdParty/mbedtls/library/ecp_curves.c"
        # SIGNATURE ------------------------------------------------------------
        "3rdParty/mbedtls/library/oid.c"
        "3rdParty/mbedtls/library/rsa.c"
        "3rdParty/mbedtls/library/rsa_internal.c"
        # Temporary: For mbedTLS
        "3rdParty/mbedtls/library/asn1parse.c"
        "3rdParty/mbedtls/library/pem.c"
        "3rdParty/mbedtls/library/base64.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "3rdParty/mbedtls/include"
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/MbedTLS_Config.h"
)


#------------------------------------------------------------------------------
project(seos_crypto C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_CryptoLib.c"
        "src/OS_Crypto.c"
        "src/util/PtrVector.c"
        "src/lib/OS_CryptoLibAgreement.c"
        "src/lib/OS_CryptoLibRng.c"
        "src/lib/OS_CryptoLibDigest.c"
        "src/lib/OS_CryptoLibMac.c"
        "src/lib/OS_CryptoLibCipher.c"
        "src/lib/OS_CryptoLibSignature.c"
        "src/lib/OS_CryptoLibKey.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)
target_link_libraries(${PROJECT_NAME}
    INTERFACE
        seos_core_api
        seos_crypto_impl_mbedtls
)


#------------------------------------------------------------------------------

project(seos_crypto_with_rpc_client C)

add_library(${PROJECT_NAME} INTERFACE)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        "src/OS_CryptoRpcClient.c"
        "src/OS_CryptoRouter.c"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        seos_core_api
        seos_crypto
)


#------------------------------------------------------------------------------

project(seos_crypto_with_rpc_server C)

add_library(${PROJECT_NAME} INTERFACE)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        "src/OS_CryptoRpcServer.c"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        seos_core_api
        seos_crypto
)

#------------------------------------------------------------------------------

# if invoked from the SEOS sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    seos_create_doxygen_target( seos_crypto_doc
        # API header is documented as part of seos_core_api, so we do nothing
        "echo"
        # API header is documented as part of seos_core_api, so we do nothing
        "echo"
    )

endif()
