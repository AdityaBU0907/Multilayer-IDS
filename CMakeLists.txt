# CMakeLists.txt — OMNeT++ Multi-Layer IDS Project
# ───────────────────────────────────────────────────────────────────────
# Requires: OMNeT++ 6.x installed, $OMNETPP_ROOT set
#
# Build steps:
#   mkdir build && cd build
#   cmake .. -DOMNETPP_ROOT=$OMNETPP_ROOT
#   make -j$(nproc)
# ───────────────────────────────────────────────────────────────────────

cmake_minimum_required(VERSION 3.16)
project(MultiLayerIDS CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Find OMNeT++ ──────────────────────────────────────────────────────
if(NOT DEFINED OMNETPP_ROOT)
    set(OMNETPP_ROOT $ENV{OMNETPP_ROOT})
endif()
if(NOT OMNETPP_ROOT)
    message(FATAL_ERROR "Set OMNETPP_ROOT to your OMNeT++ installation path")
endif()

set(CMAKE_MODULE_PATH "${OMNETPP_ROOT}/misc/cmake" ${CMAKE_MODULE_PATH})
find_package(OmnetPP REQUIRED)

# ── Message compilation ───────────────────────────────────────────────
# Run opp_msgc on .msg files to generate _m.h / _m.cc
set(MSG_FILES
    src/common/SensorPacket.msg
    src/common/IDSAlert.msg
)

set(GENERATED_SRCS "")
foreach(MSG ${MSG_FILES})
    get_filename_component(MSG_BASE ${MSG} NAME_WE)
    get_filename_component(MSG_DIR  ${MSG} DIRECTORY)
    add_custom_command(
        OUTPUT  ${MSG_DIR}/${MSG_BASE}_m.cc ${MSG_DIR}/${MSG_BASE}_m.h
        COMMAND ${OMNETPP_ROOT}/bin/opp_msgc
                --msg6 -s _m.cc
                ${CMAKE_SOURCE_DIR}/${MSG}
        DEPENDS ${MSG}
        WORKING_DIRECTORY ${MSG_DIR}
        COMMENT "Compiling message: ${MSG}"
    )
    list(APPEND GENERATED_SRCS ${MSG_DIR}/${MSG_BASE}_m.cc)
endforeach()

# ── Collect all source files ──────────────────────────────────────────
file(GLOB_RECURSE APP_SRCS
    src/mist/*.cc
    src/edge/*.cc
    src/fog/*.cc
    src/cloud/*.cc
)

# ── Main simulation executable ────────────────────────────────────────
add_executable(multilayer_ids
    ${APP_SRCS}
    ${GENERATED_SRCS}
)

target_include_directories(multilayer_ids PRIVATE
    ${OMNETPP_ROOT}/include
    src/
    src/common/
    src/lookupTables/
)

target_link_libraries(multilayer_ids PRIVATE
    ${OMNETPP_ROOT}/lib/liboppsim_dbg.so  # Use release: liboppsim.so for production
)

target_compile_options(multilayer_ids PRIVATE
    -Wall -Wextra -O2
    -DOMNETPP_VERSION=0x0600
)

# ── NED file paths (passed to opp_run at runtime) ─────────────────────
set(NED_PATHS
    ${CMAKE_SOURCE_DIR}/src/mist
    ${CMAKE_SOURCE_DIR}/src/edge
    ${CMAKE_SOURCE_DIR}/src/fog
    ${CMAKE_SOURCE_DIR}/src/cloud
    ${CMAKE_SOURCE_DIR}/simulations
    ${OMNETPP_ROOT}/src/ned
)
string(JOIN ":" NED_PATH_STR ${NED_PATHS})

# ── Convenience run targets ───────────────────────────────────────────
add_custom_target(run_multilayer
    COMMAND ${OMNETPP_ROOT}/bin/opp_run
            -l ${CMAKE_BINARY_DIR}/multilayer_ids
            -n ${NED_PATH_STR}
            -c MultiLayer
            ${CMAKE_SOURCE_DIR}/simulations/omnetpp.ini
    DEPENDS multilayer_ids
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running MultiLayer configuration"
)

add_custom_target(run_all_configs
    COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/run_all.sh
    DEPENDS multilayer_ids
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running all experiment configurations"
)

message(STATUS "OMNeT++ root : ${OMNETPP_ROOT}")
message(STATUS "NED paths    : ${NED_PATH_STR}")
