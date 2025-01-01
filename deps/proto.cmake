# Protocol buffer files embedding specifics (with compilation)
set(BUFFER_OUT "${PROJECT_SOURCE_DIR}/src/utils/protobuf")
set(BUFFER_DIR "${PROJECT_SOURCE_DIR}/src/utils/protobuf")
if (NOT TAN_PROTOREADY)
    file(GLOB_RECURSE BINARIES ${BUFFER_DIR}/*.h ${BUFFER_DIR}/*.cc)
    list(LENGTH BINARIES BINARIES_SIZE)
    if (BINARIES_SIZE GREATER 0)
        file(REMOVE ${BINARIES})
    endif()
    set(TAN_PROTOREADY ON CACHE BOOL "Do not use: for internal state management")
endif()
file(GLOB_RECURSE BINARIES ${BUFFER_DIR}/*.proto)
protobuf_generate(
    TARGET tangent
    LANGUAGE cpp
    IMPORT_DIRS "${BUFFER_OUT}"
    PROTOC_OUT_DIR "${BUFFER_OUT}")
message(STATUS "Protocol buffer data have been configured to: ${BUFFER_OUT}")