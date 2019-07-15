# SEOS Crypto Library

project(seos_crypto C)

if (ENABLE_LINT)
        set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
        set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

target_compile_options(${PROJECT_NAME}
    PUBLIC
        -Wall
        -Werror
)

if (DEBUG_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "DEBUG_CONFIG_H_FILE=${DEBUG_CONFIG_H_FILE}"
    )
endif()

if (MEMORY_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "MEMORY_CONFIG_H_FILE=${MEMORY_CONFIG_H_FILE}"
    )
endif()

if (SEOS_CRYPTO_IMPL_MBEDTLS)
    list(APPEND PRIVATE_TARGET_COMPILE_DEFINITIONS
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/MbedTLS_Config.h"
    )
    target_include_directories(${PROJECT_NAME}
        PUBLIC
        "3rdParty/mbedtls/include"
    )
    target_sources(${PROJECT_NAME}
        PRIVATE
        "src/seos/seos_rng.c"
        "3rdParty/mbedtls/library/md5.c"
        "3rdParty/mbedtls/library/platform_util.c"
        "3rdParty/mbedtls/library/entropy.c"
        "3rdParty/mbedtls/library/ctr_drbg.c"
        "3rdParty/mbedtls/library/sha1.c"
        "3rdParty/mbedtls/library/sha256.c"
        "3rdParty/mbedtls/library/sha512.c"
        "3rdParty/mbedtls/library/sha256.c"
        "3rdParty/mbedtls/library/aes.c"
        #RSA dependencies
        "3rdParty/mbedtls/library/md.c"
        "3rdParty/mbedtls/library/md_wrap.c"
        "3rdParty/mbedtls/library/bignum.c"
        "3rdParty/mbedtls/library/oid.c"
        "3rdParty/mbedtls/library/rsa.c"
        "3rdParty/mbedtls/library/rsa_internal.c"
    )
endif()

target_sources(${PROJECT_NAME}
    PRIVATE
    "src/seos/SeosCrypto.c"
    "src/seos/SeosCryptoRng.c"
    "src/seos/SeosCryptoDigest.c"
    "src/seos/SeosCryptoCipher.c"
    "src/seos/SeosCryptoSignature.c"
    "src/seos/SeosCryptoKey.c"
)

if (SEOS_CRYPTO_COMPONENT)
    target_sources(${PROJECT_NAME}
        PRIVATE
        "src/seos/SeosCryptoClient.c"
        "src/seos/SeosCryptoRpc.c"
    )
endif()

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "include"
        "include/seos"
)
