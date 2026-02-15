cmake_minimum_required(VERSION 3.22.1)
project(syncterm-native LANGUAGES C)

# Compiler flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-unused-variable -Wno-unused-function -Wno-missing-braces")

# Android-specific definitions
add_compile_definitions(
    __unix__
    __ANDROID__
    _REENTRANT
    ANDROID_CIOLIB
    HAS_INTTYPES_H
    LINK_LIST_THREADSAFE
    XPDEV_THREADSAFE
    # Note: WITHOUT_CRYPTLIB removed to enable SSH support
    # SSH requires cryptlib to be built for Android NDK
    S_IWRITE=S_IWUSR  # Windows compatibility - map to POSIX
    S_IREAD=S_IRUSR
    L_SET=SEEK_SET    # Old-style seek constants
    L_INCR=SEEK_CUR
    L_XTND=SEEK_END
)

# Cryptlib for SSH support
# Using Synchronet-patched cryptlib v3.4.8 with SSH multichannel extensions
set(CRYPTLIB_DIR ${CMAKE_SOURCE_DIR}/cryptlib)
set(HAVE_CRYPTLIB TRUE)

# Add cryptlib include directory
include_directories(${CRYPTLIB_DIR}/include)

message(STATUS "SSH enabled - using Synchronet cryptlib")

# Source directories (4 levels up from app/src/main/cpp to project root)
set(SRC_ROOT ${CMAKE_SOURCE_DIR}/../../../../src)
set(XPDEV_DIR ${SRC_ROOT}/xpdev)
set(SYNCTERM_DIR ${SRC_ROOT}/syncterm)
set(SBBS3_DIR ${SRC_ROOT}/sbbs3)
set(CONIO_DIR ${SRC_ROOT}/conio)
set(ENCODE_DIR ${SRC_ROOT}/encode)
set(HASH_DIR ${SRC_ROOT}/hash)
set(UIFC_DIR ${SRC_ROOT}/uifc)
set(SFTP_DIR ${SRC_ROOT}/sftp)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${XPDEV_DIR}
    ${SYNCTERM_DIR}
    ${SBBS3_DIR}
    ${CONIO_DIR}
    ${ENCODE_DIR}
    ${HASH_DIR}
    ${UIFC_DIR}
    ${SFTP_DIR}
)

# xpdev sources - cross-platform utilities
set(XPDEV_SOURCES
    ${XPDEV_DIR}/genwrap.c
    ${XPDEV_DIR}/sockwrap.c
    ${XPDEV_DIR}/threadwrap.c
    ${XPDEV_DIR}/strwrap.c
    ${XPDEV_DIR}/filewrap.c
    ${XPDEV_DIR}/dirwrap.c
    ${XPDEV_DIR}/ini_file.c
    ${XPDEV_DIR}/str_list.c
    ${XPDEV_DIR}/link_list.c
    ${XPDEV_DIR}/semwrap.c
    ${XPDEV_DIR}/xpevent.c
    ${XPDEV_DIR}/datewrap.c
    ${XPDEV_DIR}/xpprintf.c
    ${XPDEV_DIR}/netwrap.c
    ${XPDEV_DIR}/multisock.c
    ${XPDEV_DIR}/xpdatetime.c
    ${XPDEV_DIR}/unicode.c
)

# Encode sources - encoding utilities
set(ENCODE_SOURCES
    ${ENCODE_DIR}/utf8.c
    ${ENCODE_DIR}/base64.c
)

# Hash sources - CRC functions
set(HASH_SOURCES
    ${HASH_DIR}/crc16.c
    ${HASH_DIR}/crc32.c
)

# SBBS3 sources - telnet protocol and file transfer
set(SBBS3_SOURCES
    ${SBBS3_DIR}/telnet.c
    ${SBBS3_DIR}/zmodem.c
    ${SBBS3_DIR}/xmodem.c
)

# Terminal emulation sources from conio
set(CTERM_SOURCES
    ${CONIO_DIR}/cterm.c
    ${CONIO_DIR}/vidmodes.c
    ${CONIO_DIR}/utf8_codepages.c
    ${CONIO_DIR}/allfonts.c
)

# SyncTERM core sources - connection management
set(SYNCTERM_SOURCES
    ${SYNCTERM_DIR}/conn.c
    ${SYNCTERM_DIR}/conn_telnet.c
    ${SYNCTERM_DIR}/telnet_io.c
    ${SYNCTERM_DIR}/rlogin.c
)

# Add SSH and SFTP sources when cryptlib is available
if(HAVE_CRYPTLIB)
    list(APPEND SYNCTERM_SOURCES
        ${SYNCTERM_DIR}/ssh.c
        ${SFTP_DIR}/sftp_str.c
        ${SFTP_DIR}/sftp_pkt.c
        ${SFTP_DIR}/sftp_client.c
        ${SFTP_DIR}/sftp_attr.c
    )
endif()

# Android-specific sources
set(ANDROID_SOURCES
    ${CMAKE_SOURCE_DIR}/syncterm_jni.c
    ${CMAKE_SOURCE_DIR}/android_ciolib.c
    ${CMAKE_SOURCE_DIR}/android_stubs.c
    ${CMAKE_SOURCE_DIR}/zmodem_jni.c
)

# Build shared library
add_library(syncterm-native SHARED
    ${XPDEV_SOURCES}
    ${ENCODE_SOURCES}
    ${HASH_SOURCES}
    ${SBBS3_SOURCES}
    ${CTERM_SOURCES}
    ${SYNCTERM_SOURCES}
    ${ANDROID_SOURCES}
)

# Link libraries
target_link_libraries(syncterm-native
    android
    log
)

# Link cryptlib for SSH support
if(HAVE_CRYPTLIB)
    target_link_libraries(syncterm-native
        ${CRYPTLIB_DIR}/${ANDROID_ABI}/libcl.a
    )
endif()

# Additional target-specific compile definitions
target_compile_definitions(syncterm-native PRIVATE
    CIOLIB_NO_BEEP
)
