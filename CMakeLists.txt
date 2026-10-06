cmake_minimum_required(VERSION 3.20)
project(FarCry4Camera LANGUAGES CXX)

add_library(FarCry4Camera SHARED
    src/dllmain.cpp
)

target_compile_features(FarCry4Camera PRIVATE cxx_std_20)
target_compile_definitions(FarCry4Camera PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(FarCry4Camera PRIVATE psapi)

if(MSVC)
    target_compile_options(FarCry4Camera PRIVATE /W4 /permissive-)
endif()

set_target_properties(FarCry4Camera PROPERTIES
    OUTPUT_NAME "FarCry4Camera_v0.2"
)
