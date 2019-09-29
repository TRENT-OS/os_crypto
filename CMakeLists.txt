# SEOS Crypto Library

project(seos_crypto C)

add_library(
    ${PROJECT_NAME} STATIC

    "src/SeosCrypto.c"
    "src/SeosCryptoAgreement.c"
    "src/SeosCryptoRng.c"
    "src/SeosCryptoDigest.c"
    "src/SeosCryptoCipher.c"
    "src/SeosCryptoSignature.c"
    "src/SeosCryptoKey.c"
    "src/SeosCryptoApi.c"
    "src/SeosCryptoClient.c"
)
if (ENABLE_LINT)
        set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
        set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

# when building for the x64 architecture, some warnings are
# reported (i.e. printf formatting) that the code is full of,
# and that are otherwise not reported, so as a quick fix we
# remove the -Werror in this build situation
if(NO_KERNEL_BUILD)
    # when building for the x64 architecture, some warnings are
    # reported (i.e. printf formatting) that the code is full of,
    # and that are otherwise not reported, so as a quick fix we
    # remove the -Werror in this build situation
    target_compile_options(${PROJECT_NAME}
        PUBLIC
            -Wall
    )

    # since PAGE_SIZE is normally defined as part of musllibc
    # (which is missing here) we have to define it
    target_compile_definitions(${PROJECT_NAME} PRIVATE PAGE_SIZE=${PAGE_SIZE_VALUE})
else()
    target_compile_options(${PROJECT_NAME}
        PUBLIC
            -Wall
            -Werror
    )
endif(NO_KERNEL_BUILD)

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
        "3rdParty/mbedtls/library/md5.c"
        "3rdParty/mbedtls/library/platform_util.c"
        "3rdParty/mbedtls/library/entropy.c"
        "3rdParty/mbedtls/library/ctr_drbg.c"
        "3rdParty/mbedtls/library/sha1.c"
        "3rdParty/mbedtls/library/sha256.c"
        "3rdParty/mbedtls/library/sha512.c"
        "3rdParty/mbedtls/library/sha256.c"
        "3rdParty/mbedtls/library/aes.c"
        # GCM
        "3rdParty/mbedtls/library/gcm.c"
        "3rdParty/mbedtls/library/cipher.c"
        "3rdParty/mbedtls/library/cipher_wrap.c"
        # DH
        "3rdParty/mbedtls/library/dhm.c"
        # EC dependencies
        "3rdParty/mbedtls/library/ecdh.c"
        "3rdParty/mbedtls/library/ecp.c"
        "3rdParty/mbedtls/library/ecp_curves.c"
        # RSA dependencies
        "3rdParty/mbedtls/library/md.c"
        "3rdParty/mbedtls/library/md_wrap.c"
        "3rdParty/mbedtls/library/bignum.c"
        "3rdParty/mbedtls/library/oid.c"
        "3rdParty/mbedtls/library/rsa.c"
        "3rdParty/mbedtls/library/rsa_internal.c"
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
)

target_link_libraries(${PROJECT_NAME}
    seos_libs
    seos_core_api
)

# if invoked from the SOES sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    get_target_property(
        SEOS_CORE_API_INCLUDES
        seos_core_api
        INTERFACE_INCLUDE_DIRECTORIES)

    find_file(
        SEOS_CRYPTO_API_HEADER
        SeosCryptoApi.h
        PATHS ${SEOS_CORE_API_INCLUDES}
        CMAKE_FIND_ROOT_PATH_BOTH)

    seos_create_doxygen_target( seos_crypto_doc
        # pre-step: link the API file SeosCryptoApi.h from seos_core_api in
        #           order to produce a complete doxygen documentation
        "ln -sf ${SEOS_CRYPTO_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include"
        # post-step: remove the link to SeosCryptoApi.h
        "rm ${CMAKE_CURRENT_SOURCE_DIR}/include/SeosCryptoApi.h"
        )

endif()
