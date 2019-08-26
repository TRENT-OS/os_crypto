# SEOS Crypto Library

project(seos_crypto C)

add_library(
    ${PROJECT_NAME} STATIC

    "src/SeosCrypto.c"
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
        "src/seos_rng.c"
        "3rdParty/mbedtls/library/md5.c"
        "3rdParty/mbedtls/library/platform_util.c"
        "3rdParty/mbedtls/library/entropy.c"
        "3rdParty/mbedtls/library/ctr_drbg.c"
        "3rdParty/mbedtls/library/sha1.c"
        "3rdParty/mbedtls/library/sha256.c"
        "3rdParty/mbedtls/library/sha512.c"
        "3rdParty/mbedtls/library/sha256.c"
        "3rdParty/mbedtls/library/aes.c"
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

get_target_property(SEOS_CORE_API_INCLUDES seos_core_api INTERFACE_INCLUDE_DIRECTORIES)
find_file(SEOS_CRYPTO_API_HEADER SeosCryptoApi.h PATHS ${SEOS_CORE_API_INCLUDES} CMAKE_FIND_ROOT_PATH_BOTH)

find_package(Doxygen
             REQUIRED dot
             OPTIONAL_COMPONENTS mscgen dia)
if (DOXYGEN_FOUND)
    # note the option ALL which allows to build the docs together with the application
    add_custom_target( seos_crypto_doc
        COMMAND ln -sf ${SEOS_CRYPTO_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include
            && ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
            && ln -sf ${CMAKE_CURRENT_SOURCE_DIR}/html ${CMAKE_CURRENT_BINARY_DIR}/seos_crypto_doc
            && rm -f ${CMAKE_CURRENT_SOURCE_DIR}/include/SeosCryptoApi.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
else(DOXYGEN_FOUND)
    message("Doxygen needs to be installed to generate the doxygen documentation")
endif(DOXYGEN_FOUND)

