cmake_minimum_required(VERSION 3.10)

set(VI_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/vitex CACHE STRING "Directory: vitex")
set(VI_ANGELSCRIPT ON CACHE BOOL "-")
set(VI_BINDINGS OFF CACHE BOOL "-")
set(VI_MONGOC OFF CACHE BOOL "-")
set(VI_POSTGRESQL OFF CACHE BOOL "-")
set(VI_PUGIXML OFF CACHE BOOL "-")
include(${VI_DIRECTORY}/deps/toolchain.cmake)

project(tangentcash)
add_compile_definitions(AS_MAX_PORTABILITY)
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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.table*)
foreach(ITEM IN ITEMS ${SOURCE})
    get_filename_component(ITEM_PATH "${ITEM}" PATH)
    string(REPLACE "${PROJECT_SOURCE_DIR}" "" ITEM_GROUP "${ITEM_PATH}")
    string(REPLACE "/" "\\" ITEM_GROUP "${ITEM_GROUP}")
    source_group("${ITEM_GROUP}" FILES "${ITEM}")
endforeach()

set(TAN_TEST OFF CACHE BOOL "Build in testing mode")
if (TAN_TEST)
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
target_precompile_headers(tangentcash PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_LIST_DIR}/src/tangent/kernel/chain.h>)
if (MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "/ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE")
    target_compile_definitions(tangentcash PRIVATE -D_CRT_SECURE_NO_WARNINGS)
endif()
if (TAN_TEST)
    target_compile_definitions(tangentcash PUBLIC -DTAN_TEST)
endif()

set(VI_SOURCE_EXCLUDE "as_compiler.cpp|as_tokenizer.cpp")
add_subdirectory(${VI_DIRECTORY} vitex)
target_link_libraries(tangentcash PRIVATE vitex)
target_include_directories(tangentcash PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/vitex/deps/angelscript/sdk/angelscript/include
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/vitex/deps/angelscript/sdk/angelscript/source
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/vitex/deps/rapidjson/include)
include(deps/externals.cmake)