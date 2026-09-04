cmake_minimum_required(VERSION 3.20)

project(omp_async_crypto LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

set(SAMP_PLUGIN_SDK_DIR "" CACHE PATH "Path to samp-plugin-sdk checkout. If empty, CMake fetches it from GitHub.")

if(SAMP_PLUGIN_SDK_DIR)
  set(SAMP_PLUGIN_SDK_INCLUDE_DIR "${SAMP_PLUGIN_SDK_DIR}")
else()
  FetchContent_Declare(
    samp-plugin-sdk
    GIT_REPOSITORY https://github.com/maddinat0r/samp-plugin-sdk.git
    GIT_TAG master
  )
  FetchContent_MakeAvailable(samp-plugin-sdk)
  set(SAMP_PLUGIN_SDK_INCLUDE_DIR "${samp-plugin-sdk_SOURCE_DIR}")
endif()

FetchContent_Declare(
  argon2
  GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
  GIT_TAG master
)
FetchContent_MakeAvailable(argon2)

add_library(argon2_static STATIC
  ${argon2_SOURCE_DIR}/src/argon2.c
  ${argon2_SOURCE_DIR}/src/core.c
  ${argon2_SOURCE_DIR}/src/encoding.c
  ${argon2_SOURCE_DIR}/src/ref.c
  ${argon2_SOURCE_DIR}/src/thread.c
  ${argon2_SOURCE_DIR}/src/blake2/blake2b.c
)

target_include_directories(argon2_static PUBLIC
  ${argon2_SOURCE_DIR}/include
  ${argon2_SOURCE_DIR}/src
)

target_compile_definitions(argon2_static PRIVATE ARGON2_NO_THREADS)
set_target_properties(argon2_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(omp_async_crypto SHARED
  src/plugin.cpp
  src/crypto_utils.cpp
  ${SAMP_PLUGIN_SDK_INCLUDE_DIR}/amxplugin.cpp
)

target_include_directories(omp_async_crypto PRIVATE
  ${SAMP_PLUGIN_SDK_INCLUDE_DIR}
  ${SAMP_PLUGIN_SDK_INCLUDE_DIR}/amx
  ${argon2_SOURCE_DIR}/include
  src
)

target_link_libraries(omp_async_crypto PRIVATE
  argon2_static
)

if(WIN32)
  target_link_libraries(omp_async_crypto PRIVATE bcrypt)
  target_compile_definitions(omp_async_crypto PRIVATE HAVE_STDINT_H)
  if(MINGW)
    target_link_options(omp_async_crypto PRIVATE -Wl,--kill-at)
  endif()
endif()

if(MSVC)
  target_sources(omp_async_crypto PRIVATE exports/async_crypto.def)
  target_compile_definitions(omp_async_crypto PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(omp_async_crypto PRIVATE -Wall -Wextra -Wpedantic)
  target_link_options(omp_async_crypto PRIVATE -static-libstdc++ -static-libgcc)
  if(WIN32)
    target_compile_options(omp_async_crypto PRIVATE "-include${CMAKE_CURRENT_SOURCE_DIR}/src/mingw_compat.h")
  endif()
  if(UNIX)
    target_compile_definitions(omp_async_crypto PRIVATE LINUX)
    target_link_options(omp_async_crypto PRIVATE -Wl,--no-undefined)
  endif()
endif()

set_target_properties(omp_async_crypto PROPERTIES
  PREFIX ""
  OUTPUT_NAME "async_crypto"
)
