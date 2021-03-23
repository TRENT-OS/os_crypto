# OS Crypto

## Overview

OS Crypto Library provides a library that allows components to run crypto
routines either locally or via the CryptoServer

## Usage

The project creates a CMake interface library called os_crypto which can be
statically linked by other projects that depend on it (libraries, components
etc.).

### Dependencies

* configuration files
* mbedTLS (provides the actual crypto implementation)
