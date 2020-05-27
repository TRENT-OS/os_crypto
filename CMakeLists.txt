#
# OS Crypto Library
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

# We need to build 3rdparty/mbedtls for this and would like to avoid
# all users of OS_CRYPTO to include this as well, so we do it here
seos_use_libs(
    3RDPARTY_MBEDTLS_FOR_CRYPTO
)

# These are the sources we ALWAYS compile, for all targets
set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_Crypto.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_CryptoAgreement.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_CryptoCipher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_CryptoDigest.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_CryptoKey.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_CryptoMac.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_CryptoRng.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/OS_CryptoSignature.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLib.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLibAgreement.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLibRng.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLibDigest.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLibMac.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLibCipher.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLibSignature.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/CryptoLibKey.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/util/PtrVector.c"
)

set(COMPILE_DEFINITIONS)

set(COMPILE_OTIONS
    -Wall
)

# when building for the x64 architecture, some warnings are reported (i.e. printf
# formatting) that the code is full of, and that are otherwise not reported, so as
# a quick fix we don't add -Werror when compiling in this situation
if(NO_KERNEL_BUILD)
    # since PAGE_SIZE is normally defined as part of musllibc (which is missing
    # here) we have to define it
    set(COMPILE_OTIONS
        ${COMPILE_OTIONS}
        PAGE_SIZE=${PAGE_SIZE_VALUE}
    )
else()
    set(COMPILE_OTIONS
        ${COMPILE_OTIONS}
        -Werror
    )
endif(NO_KERNEL_BUILD)

if (ENABLE_LINT)
    set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

#------------------------------------------------------------------------------

project(seos_crypto C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES}
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
       ${COMPILE_OPTIONS}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_crypto
        seos_core_api
        seos_libs
)

#------------------------------------------------------------------------------

project(seos_crypto_with_rpc_client C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/CryptoLibClient.c"
        ${SOURCES}
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
       ${COMPILE_OPTIONS}
       -DOS_CRYPTO_WITH_RPC_CLIENT
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_crypto
        seos_core_api
        seos_libs
)

#------------------------------------------------------------------------------

project(seos_crypto_with_rpc_server C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/CryptoLibServer.c"
        ${SOURCES}
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
       ${COMPILE_OPTIONS}
       -DOS_CRYPTO_WITH_RPC_SERVER
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_crypto
        seos_core_api
        seos_libs
)

#------------------------------------------------------------------------------

# if invoked from the OS sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    seos_create_doxygen_target( seos_crypto_doc
        # API header is documented as part of seos_core_api, so we do nothing
        "echo"
        # API header is documented as part of seos_core_api, so we do nothing
        "echo"
    )

endif()