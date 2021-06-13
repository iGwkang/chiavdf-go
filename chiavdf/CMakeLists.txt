CMAKE_MINIMUM_REQUIRED(VERSION 3.14 FATAL_ERROR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)


IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "RELEASE")
ENDIF()

project(chiavdf)

set(CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/cmake
    ${CMAKE_MODULE_PATH}
)

find_package(GMP REQUIRED)
find_package(GMPXX REQUIRED)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${GMP_INCLUDE_DIR}
  ${GMPXX_INCLUDE_DIR}
)

#aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} chiavdf_src)
#aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/uint128_t chiavdf_src)

set (LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/go_bindings)

add_library(chiavdf STATIC
 # ${CMAKE_CURRENT_SOURCE_DIR}/python_bindings/fastvdf.cpp
 ${chiavdf_src}
${CMAKE_CURRENT_SOURCE_DIR}/go_bindings/fastvdf.cpp
${CMAKE_CURRENT_SOURCE_DIR}/refcode/lzcnt.c
)

#target_link_libraries(chiavdf ${GMP_LIBRARIES} ${GMPXX_LIBRARIES} -pthread)
