cmake_minimum_required(VERSION 3.22)

project(easy_aes)

include_directories(${PROJECT_SOURCE_DIR})

add_library( ssl
             STATIC
             IMPORTED)
set_target_properties( ssl
                       PROPERTIES IMPORTED_LOCATION
                       ${PROJECT_SOURCE_DIR}/lib/libssl.lib )

add_library( crypto
             STATIC
             IMPORTED)
set_target_properties( crypto
                       PROPERTIES IMPORTED_LOCATION
                       ${PROJECT_SOURCE_DIR}/lib/libcrypto.lib )

add_executable( eaes 
                main.cpp security.cpp base64.cpp )

target_link_libraries( eaes
                       ssl crypto )