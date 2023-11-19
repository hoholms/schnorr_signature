cmake_minimum_required(VERSION 3.26)
project(schnorr_signature)

set(CMAKE_CXX_STANDARD 23)

include_directories(/opt/homebrew/Cellar/openssl@3/3.1.4/include)
link_directories(/opt/homebrew/Cellar/openssl@3/3.1.4/lib)

add_executable(schnorr_signature main.cpp
        SchnorrSignature.h
        SchnorrSignature.cpp)

target_compile_options(schnorr_signature PRIVATE -Wno-deprecated-declarations)
target_link_libraries(schnorr_signature PRIVATE ssl crypto)
