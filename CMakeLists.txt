cmake_minimum_required(VERSION 3.12)

set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})

project(upselling_config VERSION ${PROJECT_VERSION})

option(WITH_BOOST_TEST "Whether to build Boost test" OFF)
option(WITH_GTEST "Whether to build Google test" ON)

add_definitions(-D USE_PRETTY)

add_subdirectory(libplcore)
add_subdirectory(plcfg_cli)
add_subdirectory(plcrypt)

install(TARGETS plcfg_cli RUNTIME DESTINATION bin)
install(TARGETS plcrypt RUNTIME DESTINATION bin)
install(TARGETS plcore LIBRARY DESTINATION lib)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_CONTACT m.fukalov@frendit.ru)
include(CPack)

if(WITH_GTEST)
    enable_testing()
    add_test(settingstest libplcore/tests/settingstest/settingstest)
endif()
