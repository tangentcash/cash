cmake_minimum_required(VERSION 3.10)

set(VI_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/vitex CACHE STRING "Vitex directory")
set(VI_BINDINGS OFF CACHE BOOL "-")
set(VI_MONGOC OFF CACHE BOOL "-")
set(VI_POSTGRESQL OFF CACHE BOOL "-")
set(VI_PUGIXML OFF CACHE BOOL "-")
include(${VI_DIRECTORY}/deps/toolchain.cmake)

project(tangent)
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

set(TAN_TEST OFF CACHE BOOL "Enable validator tests")
if (TAN_TEST)
    list(FILTER SOURCE EXCLUDE REGEX "src/main")
else()
    list(FILTER SOURCE EXCLUDE REGEX "src/test")
endif()

add_executable(tangent ${SOURCE})
set_target_properties(tangent PROPERTIES
    OUTPUT_NAME "tangentd"
    CXX_STANDARD ${VI_CXX}
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION})
target_compile_definitions(tangent PUBLIC -DTAN_VALIDATOR)
target_precompile_headers(tangent PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:${VI_DIRECTORY}/src/vitex/bindings.h>
    $<$<COMPILE_LANGUAGE:CXX>:${VI_DIRECTORY}/src/vitex/compute.h>
    $<$<COMPILE_LANGUAGE:CXX>:${VI_DIRECTORY}/src/vitex/layer/processors.h>
    $<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_LIST_DIR}/src/tangent/kernel/chain.h>
    $<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_LIST_DIR}/src/tangent/kernel/mediator.h>)
if (MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "/ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE")
    target_compile_definitions(tangent PRIVATE -D_CRT_SECURE_NO_WARNINGS)
    target_compile_options(tangent PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/wd4146>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4244>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4251>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4275>)
endif()

add_subdirectory(${VI_DIRECTORY} vitex)
link_directories(${VI_DIRECTORY})
target_include_directories(tangent PRIVATE ${VI_DIRECTORY})
target_link_libraries(tangent PRIVATE vitex)
target_include_directories(tangent PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../)
include(deps/externals.cmake)