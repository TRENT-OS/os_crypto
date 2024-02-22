# OS Crypto

## Overview

OS Crypto allows components to run crypto routines either locally or via the
CryptoServer.

## Usage

The project creates a CMake interface library called os_crypto which can be
statically linked by other projects that depend on it (libraries, components
etc.).

### Dependencies

- mbedTLS (provides the actual crypto implementation)


## 3rd Party Modules

The table lists the 3rd party modules used within this module, their licenses
and the source from which they were obtained:

| Name                              | SPDX Identifier | Source                               |
|-----------------------------------|-----------------|--------------------------------------|
| mbedtls                           | Apache-2.0      | <https://github.com/ARMmbed/mbedtls> |
| src/lib/primitives/CryptoLibAes.c | MIT             | <https://github.com/aadomn/aes>      |
