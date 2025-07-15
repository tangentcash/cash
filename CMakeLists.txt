cmake_minimum_required(VERSION 3.10)

set(VI_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/vitex CACHE STRING "Directory: vitex")
set(VI_BINDINGS OFF CACHE BOOL "-")
set(VI_MONGOC OFF CACHE BOOL "-")
set(VI_POSTGRESQL OFF CACHE BOOL "-")
set(VI_PUGIXML OFF CACHE BOOL "-")
include(${VI_DIRECTORY}/deps/toolchain.cmake)

project(tangentcash)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

if (NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_SOURCE_DIR}/bin)
endif()

file(GLOB_RECURSE SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.inc*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.table*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.proto*)
foreach(ITEM IN ITEMS ${SOURCE})
    get_filename_component(ITEM_PATH "${ITEM}" PATH)
    string(REPLACE "${PROJECT_SOURCE_DIR}" "" ITEM_GROUP "${ITEM_PATH}")
    string(REPLACE "/" "\\" ITEM_GROUP "${ITEM_GROUP}")
    source_group("${ITEM_GROUP}" FILES "${ITEM}")
endforeach()

set(TAN_BUILD "main" CACHE STRING "Build target: \"lib\" | \"main\" | \"test\"")
if (${TAN_BUILD} STREQUAL "main" OR ${TAN_BUILD} STREQUAL "test")
    if (${TAN_BUILD} STREQUAL "test")
        list(FILTER SOURCE EXCLUDE REGEX "src/main")
    else()
        list(FILTER SOURCE EXCLUDE REGEX "src/test")
    endif()
    add_executable(tangentcash ${SOURCE})
    set_target_properties(tangentcash PROPERTIES
        OUTPUT_NAME "tangentcash"
        CXX_STANDARD ${VI_CXX}
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION})
    if (MSVC)
        set(CMAKE_EXE_LINKER_FLAGS "/ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE")
    endif()
elseif (${TAN_BUILD} STREQUAL "lib")
    list(FILTER SOURCE EXCLUDE REGEX "src/(main|test)")
    add_library(tangentcash ${SOURCE})
    set_target_properties(tangentcash PROPERTIES
        CXX_STANDARD ${VI_CXX}
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION})
else()
  message(FATAL_ERROR "Invalid build target. Expected type: \"lib\", \"main\" or \"test\"")
endif()

target_precompile_headers(tangentcash PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_LIST_DIR}/src/tangent/kernel/chain.h>)
if (MSVC)
    target_compile_definitions(tangentcash PRIVATE -D_CRT_SECURE_NO_WARNINGS)
    target_compile_options(tangentcash PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/wd4146>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4244>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4251>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4275>)
endif()

add_subdirectory(${VI_DIRECTORY} vitex)
target_link_libraries(tangentcash PRIVATE vitex)
include(deps/externals.cmake)