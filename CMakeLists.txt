cmake_minimum_required(VERSION 4.3)
project(BCrypt)

set(CMAKE_CXX_STANDARD 20)

add_library(BCrypt SHARED
        bcrypt.cpp
        bcrypt.hpp)

set_target_properties(BCrypt PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
)

target_compile_definitions(BCrypt PRIVATE BCRYPT_EXPORTS)

target_link_libraries(Test PRIVATE BCrypt)