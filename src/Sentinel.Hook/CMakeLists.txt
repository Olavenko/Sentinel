cmake_minimum_required(VERSION 3.20)
project(SentinelHook LANGUAGES C CXX)

# Force 32-bit build (Conquer.exe is x86)
set(CMAKE_GENERATOR_PLATFORM Win32 CACHE STRING "" FORCE)

# MinHook sources
set(MINHOOK_SRC
    minhook/src/buffer.c
    minhook/src/hook.c
    minhook/src/trampoline.c
    minhook/src/hde/hde32.c
    minhook/src/hde/hde64.c
)

add_library(SentinelHook SHARED
    SentinelHook.cpp
    ${MINHOOK_SRC}
)

target_include_directories(SentinelHook PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/minhook/include
    ${CMAKE_CURRENT_SOURCE_DIR}/minhook/src
)

target_link_libraries(SentinelHook PRIVATE ws2_32)

# C runtime: static link so the DLL has no CRT dependencies
set_target_properties(SentinelHook PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
    OUTPUT_NAME "SentinelHook"
    SUFFIX ".dll"
)

if(MSVC)
    target_compile_definitions(SentinelHook PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
