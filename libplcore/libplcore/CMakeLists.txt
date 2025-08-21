cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

##################### Variables ############################
# Change if you want modify path or other values           #
############################################################

# Project
set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})

get_filename_component(PROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)
set(DEPENDENCIES_DIR ${PROJECT_DIR}/../../dependslib)
set(DEPENDENCIES_LIB_DIR ${DEPENDENCIES_DIR})
set(PROJECT_NAME plcore)


# Outputs
set(OUTPUT_DEBUG ../../Debug)
set(OUTPUT_RELEASE ../../Release)

################# CMake Project ############################
# The main options of project                              #
############################################################

project(${PROJECT_NAME} VERSION ${PROJECT_VERSION} LANGUAGES CXX C)

# Define Release by default.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
  message(STATUS "Build type not specified: Use Release by default.")
endif(NOT CMAKE_BUILD_TYPE)

add_definitions(-D BOTAN_NO_DEPRECATED_WARNINGS)
if(WIN32)
  add_definitions(-D_WINDOWS)
endif(WIN32)

############## Artefacts Output ############################
# Defines outputs , depending BUILD TYPE                   #
############################################################

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_DEBUG}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_DEBUG}")
  set(RUNTIME_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_DEBUG}")
else()
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_RELEASE}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_RELEASE}")
  set(RUNTIME_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_RELEASE}")
endif()

# Messages
message("${PROJECT_NAME}: MAIN PROJECT: ${CMAKE_PROJECT_NAME}")
message("${PROJECT_NAME}: CURR PROJECT: ${CMAKE_CURRENT_SOURCE_DIR}")
message("${PROJECT_NAME}: CURR BIN DIR: ${CMAKE_CURRENT_BINARY_DIR}")
message("${PROJECT_NAME}: CMAKE_LIBRARY_OUTPUT_DIRECTORY: ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
message("${PROJECT_NAME}: CMAKE_ARCHIVE_OUTPUT_DIRECTORY: ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")
message("${PROJECT_NAME}: RUNTIME_OUTPUT_DIRECTORY: ${RUNTIME_OUTPUT_DIRECTORY}")

configure_file(version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/version.h)


############### Files & Targets ############################
# Files of project and target to build                     #
############################################################

file(GLOB PROJECT_NAME_CXX_FILES "${PROJECT_DIR}/*.cpp")
file(GLOB PROJECT_NAME_C_FILES "${PROJECT_DIR}/*.c")
file(GLOB PROJECT_NAME_HXX_FILES " ${PROJECT_DIR}/*.h*")

# Source Files
set(SRC_FILES
    ${PROJECT_NAME_CXX_FILES}
    ${PROJECT_NAME_C_FILES}
	${DEPENDENCIES_DIR}/tinyxml2/tinyxml2.cpp
	${DEPENDENCIES_DIR}/libKISSlog/src/kisslog-mt-static.cpp 
)
source_group("Sources" FILES ${SRC_FILES})

# Header Files
set(HEADERS_FILES
    ${PROJECT_NAME_HXX_FILES}
	${DEPENDENCIES_DIR}/tinyxml2/tinyxml2.h
)
source_group("Headers" FILES ${HEADERS_FILES})

include_directories(${PROJECT_NAME} 
  "${PROJECT_DIR}/../../libplcore/"
  "${DEPENDENCIES_LIB_DIR}/date-2.4.1/include/"
  "${DEPENDENCIES_LIB_DIR}/fmt-4.1.0/"
  "${DEPENDENCIES_LIB_DIR}/openssl/include/"
  "${DEPENDENCIES_LIB_DIR}/curl/include/"
  "${DEPENDENCIES_LIB_DIR}/libzip/include/"
  "${DEPENDENCIES_LIB_DIR}/libKISSlog/"
  "${DEPENDENCIES_LIB_DIR}/gsoap/"
  "${DEPENDENCIES_LIB_DIR}/tinyxml2/"
  "${DEPENDENCIES_LIB_DIR}/simpleini/include/"
  "${DEPENDENCIES_LIB_DIR}/cpr/include"
  "${DEPENDENCIES_LIB_DIR}/curlpp/include"
)


# Add executable to build.
add_library(${PROJECT_NAME} SHARED
   ${SRC_FILES} ${HEADERS_FILES}
)

set_target_properties(${PROJECT_NAME} PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
	LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
	ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}"
	RUNTIME_OUTPUT_DIRECTORY "${RUNTIME_OUTPUT_DIRECTORY}"
)


######################### Flags ############################
# Defines Flags for Windows and Linux                      #
############################################################

# Preprocessor definitions
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
   -DUNICODE
   -D_DEBUG 
   -D_CONSOLE 
   -DWITH_NONAMESPACES 
   -DZSUTILS_EXPORTS
   -DZSPOSPROCL_EXPORTS
   -DCURL_STATICLIB
    )
    if(MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE  /W3 /MDd /Od /Zi /EHsc)
	    if(NOT CMAKE_DEBUG_POSTFIX)
		    if(CMAKE_BUILD_TYPE STREQUAL "Debug")	
			   set(CMAKE_DEBUG_POSTFIX "d") 
			endif()
		endif()
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
   -DUNICODE
   -DNDEBUG 
   -D_CONSOLE 
   -DWITH_NONAMESPACES 
   -DZSUTILS_EXPORTS
   -DZSPOSPROCL_EXPORTS
   -DCURL_STATICLIB
    )
    if(MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE  /W3 /MD /GL /Zi /EHsc)
    endif()
endif()

########### Link & Dependencies ############################
# Add project dependencies and Link to project             #
############################################################


set(Boost_USE_STATIC_LIBS        OFF)  
set(Boost_USE_DEBUG_LIBS        OFF)  
set(Boost_USE_RELEASE_LIBS       ON)  
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME    OFF)
find_package(Boost 1.58.0 REQUIRED COMPONENTS program_options system)
if( Boost_FOUND )
    message(status "** Boost Include: ${Boost_INCLUDE_DIR}")
    message(status "** Boost Libraries: ${Boost_LIBRARY_DIRS}")
    message(status "** Boost Libraries: ${Boost_LIBRARIES}")

    set_target_properties(${PROJECT_NAME} PROPERTIES
        COMPILE_DEFINITIONS BOOST_ALL_DYN_LINK
    )
    target_include_directories(${PROJECT_NAME}  PUBLIC
      ${Boost_INCLUDE_DIR}
    )    
    
    target_link_libraries(${PROJECT_NAME}  PRIVATE
        ${Boost_LIBRARIES}
    )
endif()


if(MSVC)

	target_link_libraries(${PROJECT_NAME} shlwapi.lib  ws2_32.lib
	                     ${DEPENDENCIES_LIB_DIR}/libzip/lib/zip.lib
	                     ${DEPENDENCIES_LIB_DIR}/zlib/lib/zlibstatic.lib
		                  ${DEPENDENCIES_LIB_DIR}/openssl/lib/libeay32.lib 
		                  ${DEPENDENCIES_LIB_DIR}/openssl/lib/ssleay32.lib 
		                  ${DEPENDENCIES_LIB_DIR}/curl/lib/libcurl.lib 
			              ${DEPENDENCIES_LIB_DIR}/curlpp/lib/libcurlpp${CMAKE_DEBUG_POSTFIX}.lib 
   )
endif(MSVC)

