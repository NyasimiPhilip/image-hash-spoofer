cmake_minimum_required(VERSION 3.10)
project(ImageHashSpoofer C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find required libraries
find_package(OpenSSL REQUIRED)
find_package(ImageMagick COMPONENTS MagickCore MagickWand REQUIRED)

# Unity test framework (download if not present)
include(FetchContent)
FetchContent_Declare(
  unity
  GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
  GIT_TAG        v2.5.0
)
FetchContent_MakeAvailable(unity)

# Include directories
include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${IMAGEMAGICK_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/src
)

# Main executable
add_executable(spoof 
    src/spoof.c
)
target_link_libraries(spoof 
    ${OPENSSL_LIBRARIES}
    ${IMAGEMAGICK_LIBRARIES}
)

# Test executable
add_executable(test_spoof 
    src/spoof.c
    tests/test_spoof.c
    ${unity_SOURCE_DIR}/src/unity.c
)
target_include_directories(test_spoof PRIVATE 
    ${unity_SOURCE_DIR}/src
)
target_link_libraries(test_spoof 
    ${OPENSSL_LIBRARIES}
    ${IMAGEMAGICK_LIBRARIES}
)

# Add test
enable_testing()
add_test(NAME SpooferTests COMMAND test_spoof)