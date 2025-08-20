cmake_minimum_required(VERSION 3.12)

set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})

project(plcfg_cli VERSION ${PROJECT_VERSION})

option(WITH_BOOST_TEST "Whether to build Boost test" OFF)
option(WITH_GTEST "Whether to build Google test" ON)

add_subdirectory(plcfg_cli)