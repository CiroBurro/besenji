cmake_minimum_required(VERSION 4.0)
project(besenji C)

set(CMAKE_C_STANDARD 11)

include_directories(headers)

add_executable(besenji
        headers/sniffer.h
        headers/utils.h
        src/main.c
        src/sniffer.c
        src/utils.c)
