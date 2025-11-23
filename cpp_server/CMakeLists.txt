cmake_minimum_required(VERSION 3.14)
project(pqc_server CXX)

set(CMAKE_CXX_STANDARD 17)
set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../proto)
set(PROTO_FILES
    ${PROTO_DIR}/pqc.proto
    ${PROTO_DIR}/health.proto
)

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_package(OpenSSL REQUIRED)

# Find the gRPC C++ plugin executable
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
if(NOT GRPC_CPP_PLUGIN_EXECUTABLE)
    message(FATAL_ERROR "grpc_cpp_plugin not found!")
endif()

# -- Generate protobuf sources
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

# -- Generate gRPC sources
set(GRPC_SRCS)
set(GRPC_HDRS)
foreach(PROTO ${PROTO_FILES})
    get_filename_component(PROTO_NAME ${PROTO} NAME_WE)
    list(APPEND GRPC_SRCS "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.cc")
    list(APPEND GRPC_HDRS "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.h")
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.cc"
               "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.h"
        COMMAND ${Protobuf_PROTOC_EXECUTABLE}
        ARGS --grpc_out=${CMAKE_CURRENT_BINARY_DIR}
             --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
             -I${PROTO_DIR}
             ${PROTO}
        DEPENDS ${PROTO}
    )
endforeach()

add_executable(pqc_server
    main.cpp
    secure_storage.cpp
    db_manager.cpp
    http_gateway.cpp
    s3_client.cpp
    logger.cpp
    config.cpp
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)

target_include_directories(pqc_server
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${PROTO_DIR}
        ${OpenSSL_INCLUDE_DIR}
)

# Link libraries in the correct order. When gRPC is built with bundled Abseil,
# we need to explicitly add the abseil library directory to the link path.
target_link_directories(pqc_server
    PRIVATE
        /usr/local/lib
)

# The gRPC::grpc++ target should transitively bring in its dependencies,
# but when using bundled Abseil, we need to be explicit about linking.
# Link gRPC first, then add the specific missing Abseil libraries.
target_link_libraries(pqc_server
    PRIVATE
    gRPC::grpc++
    gRPC::grpc++_reflection
    protobuf::libprotobuf
    OpenSSL::SSL
    OpenSSL::Crypto
    sqlite3
    curl
    # Explicitly add the problematic Abseil library
    absl_log_internal_check_op
)

install(TARGETS pqc_server DESTINATION bin)
