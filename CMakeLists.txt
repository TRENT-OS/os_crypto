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

# These are the sources we ALWAYS compile, for all targets
set(SHARED_LIB_SOURCES
    "src/OS_Crypto.c"
    "src/OS_CryptoAgreement.c"
    "src/OS_CryptoCipher.c"
    "src/OS_CryptoDigest.c"
    "src/OS_CryptoKey.c"
    "src/OS_CryptoMac.c"
    "src/OS_CryptoRng.c"
    "src/OS_CryptoSignature.c"
    "src/OS_CryptoLib.c"
    "src/lib/OS_CryptoLibAgreement.c"
    "src/lib/OS_CryptoLibRng.c"
    "src/lib/OS_CryptoLibDigest.c"
    "src/lib/OS_CryptoLibMac.c"
    "src/lib/OS_CryptoLibCipher.c"
    "src/lib/OS_CryptoLibSignature.c"
    "src/lib/OS_CryptoLibKey.c"
    "src/util/PtrVector.c"
)

# These are the 3rd party sources, holding the actual algorithms
set(MBEDTLS_SOURCES
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

set(PRIVATE_TARGET_COMPILE_DEFINITIONS
    MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/MbedTLS_Config.h"
)

set(PUBLIC_TARGET_COMPILE_DEFINITIONS)

set(PRIVATE_TARGET_COMPILE_OTIONS)

set(PUBLIC_TARGET_COMPILE_OTIONS
    -Wall
)

# when building for the x64 architecture, some warnings are reported (i.e. printf
# formatting) that the code is full of, and that are otherwise not reported, so as
# a quick fix we don't add -Werror when compiling in this situation
if(NO_KERNEL_BUILD)
    # since PAGE_SIZE is normally defined as part of musllibc (which is missing
    # here) we have to define it
    set(PRIVATE_TARGET_COMPILE_DEFINITIONS
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
        PAGE_SIZE=${PAGE_SIZE_VALUE}
    )
else()
    set(PUBLIC_TARGET_COMPILE_OTIONS
        ${PUBLIC_TARGET_COMPILE_OTIONS}
        -Werror
    )
endif(NO_KERNEL_BUILD)

if (ENABLE_LINT)
    set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

#------------------------------------------------------------------------------

project(seos_crypto C)

add_library(${PROJECT_NAME} STATIC
    ${SHARED_LIB_SOURCES}
    ${MBEDTLS_SOURCES})

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_OPTIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_OPTIONS}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "inc"
        "3rdParty/mbedtls/include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_libs
)

#------------------------------------------------------------------------------

project(seos_crypto_with_rpc_client C)

add_library(${PROJECT_NAME} STATIC
    ${SHARED_LIB_SOURCES}
    "src/OS_CryptoRpcClient.c"
    "src/OS_CryptoRouter.c"
    ${MBEDTLS_SOURCES})

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_OPTIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_OPTIONS}
        -DSEOS_CRYPTO_WITH_RPC_CLIENT
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "inc"
        "3rdParty/mbedtls/include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_libs
)

#------------------------------------------------------------------------------

project(seos_crypto_with_rpc_server C)

add_library(${PROJECT_NAME} STATIC
    ${SHARED_LIB_SOURCES}
    "src/OS_CryptoRpcServer.c"
    ${MBEDTLS_SOURCES})

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_OPTIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_OPTIONS}
        -DSEOS_CRYPTO_WITH_RPC_SERVER
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "inc"
        "3rdParty/mbedtls/include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_libs
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