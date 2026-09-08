# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Cross-compile toolchain file for FreeBSD 15.x targets.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
# Usage (from the repository root):
#   cmake -S . -B build-freebsd \
#       -DCMAKE_TOOLCHAIN_FILE=tools/freebsd-toolchain.cmake \
#       -DFREEBSD_SYSROOT=/path/to/freebsd-sysroot \
#       -DFREEBSD_TARGET_ARCH=x86_64
#
# Host requirements:
#   - clang + lld (ld.lld) + LLVM binutils (llvm-ar, llvm-nm, llvm-ranlib,
#     llvm-readelf) on PATH.
#   - A FreeBSD 15.x sysroot, i.e. the contents of base.txz extracted so that
#     $SYSROOT/usr/include, $SYSROOT/usr/lib, $SYSROOT/lib and $SYSROOT/libexec
#     are present:
#         mkdir -p sysroot
#         tar -xf base.txz -C sysroot ./lib ./libexec ./usr/lib ./usr/include
#
#   base.txz provides only the FreeBSD base system headers and libc/libm.
#   FTL's optional third-party libraries (nettle/hogweed+gmp for DNSSEC,
#   libidn2+unistring for IDN, OpenSSL for TLS) live in /usr/local on FreeBSD
#   and must be installed into $SYSROOT/usr/local as well for those features.

set(CMAKE_SYSTEM_NAME FreeBSD)

# Map to clang's target tuple. FreeBSD arch -> clang tuple:
#   amd64   -> x86_64     (base.txz from releases/amd64/amd64/)
#   aarch64 -> aarch64    (base.txz from releases/aarch64/aarch64/)
if(NOT DEFINED FREEBSD_TARGET_ARCH)
    set(FREEBSD_TARGET_ARCH x86_64)
endif()
set(FREEBSD_TARGET_TRIPLE "${FREEBSD_TARGET_ARCH}-unknown-freebsd")

set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET ${FREEBSD_TARGET_TRIPLE})
set(CMAKE_ASM_COMPILER clang)
set(CMAKE_ASM_COMPILER_TARGET ${FREEBSD_TARGET_TRIPLE})

# The sysroot is mandatory; the compiler/CMake must not fall back to the host.
# Prefer a -D cache value passed by the caller, falling back to the
# FREEBSD_SYSROOT environment variable. Environment variables are the only
# channel that reliably reaches CMake's internal try_compile subprojects
# (compiler ABI checks, check_include_file, ...) which re-run this toolchain
# but are not given the original command-line -D flags.
if(DEFINED FREEBSD_SYSROOT AND NOT FREEBSD_SYSROOT STREQUAL "")
    set(FREEBSD_SYSROOT_PATH "${FREEBSD_SYSROOT}")
elseif(DEFINED ENV{FREEBSD_SYSROOT} AND NOT ENV{FREEBSD_SYSROOT} STREQUAL "")
    set(FREEBSD_SYSROOT_PATH "$ENV{FREEBSD_SYSROOT}")
    set(FREEBSD_SYSROOT "${FREEBSD_SYSROOT_PATH}" CACHE PATH "Path to the FreeBSD sysroot (base.txz)" FORCE)
else()
    message(FATAL_ERROR
        "No FreeBSD sysroot. Pass -DFREEBSD_SYSROOT=/path/to/freebsd-sysroot "
        "or set the FREEBSD_SYSROOT environment variable.")
endif()

set(CMAKE_SYSROOT ${FREEBSD_SYSROOT_PATH})
set(CMAKE_FIND_ROOT_PATH ${FREEBSD_SYSROOT_PATH})

# Search only inside the sysroot for headers/libs; the compiler and CMake
# scripts come from the build host.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Cross-link with lld and resolve libc/libm/crt*.o from the sysroot.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld -L${FREEBSD_SYSROOT_PATH}/usr/lib")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld -L${FREEBSD_SYSROOT_PATH}/usr/lib")

# FreeBSD ships third-party headers (nettle, gmp, libidn2, OpenSSL) under
# <sysroot>/usr/local/include, which is NOT part of clang's default search
# path (like Linux's /usr/include). Add it so the DNSSEC/IDN/TLS headers the
# port provides can be #included. -isystem avoids warnings on their contents.
set(CMAKE_C_FLAGS_INIT "-isystem ${FREEBSD_SYSROOT_PATH}/usr/local/include")
