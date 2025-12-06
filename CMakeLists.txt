cmake_minimum_required(VERSION 3.13)
project(besenji VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_executable(besenji
        src/main.c
        src/sniffer.c
        src/utils.c
)

target_include_directories(besenji PRIVATE ${CMAKE_SOURCE_DIR}/headers)

if(MSVC)
    target_compile_options(besenji PRIVATE /W4)
else()
    target_compile_options(besenji PRIVATE -Wall -Wextra)
endif()
