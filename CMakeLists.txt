cmake_minimum_required(VERSION 3.10)
project(MyProject)

include_directories(mbedtls/include)

# Add the executable
add_executable(my_app main.c keypair.c ca.c tls_test.c util.c)

# Add mbedTLS source files
file(GLOB MBEDTLS_SOURCES "mbedtls/library/*.c")
target_sources(my_app PRIVATE ${MBEDTLS_SOURCES})
