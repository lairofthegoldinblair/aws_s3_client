cmake_minimum_required (VERSION 3.2)

project (aws_s3_client)

# We have some of our own CMake Find Modules
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules/")

######################################################
######################################################
# Packages and libraries 
######################################################
######################################################

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)

#
# Boost
#
find_package( Boost 1.65.1 COMPONENTS filesystem log program_options regex system thread date_time unit_test_framework REQUIRED )
include_directories ( ${Boost_INCLUDE_DIR} )

#
# Openssl
#
find_package( OpenSSL REQUIRED )

#
# Miscellaneous libraries builtin to Linux
#
find_library(LIB_DL dl)
find_library(LIB_PTHREAD pthread)
find_library(LIB_RT rt)

#
# Setup CXX17 flag
#
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
if(COMPILER_SUPPORTS_CXX17)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
else()
        message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support. Please use a different C++ compiler.")
endif()

######################################################
######################################################
# Subdirectories of the project
######################################################
######################################################
include_directories ( "${PROJECT_SOURCE_DIR}/src" )
include_directories ( "${PROJECT_SOURCE_DIR}/lib" )

add_subdirectory ( src )
add_subdirectory ( lib )
add_subdirectory ( test )

######################################################
######################################################
# Unit testing support
######################################################
######################################################
enable_testing()
add_test(v4_signing_test ${CMAKE_CURRENT_BINARY_DIR}/test/v4_signing_test)

