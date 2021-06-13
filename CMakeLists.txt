cmake_minimum_required(VERSION 3.14)
project(chiavdf-go)

# C/C++项目
add_subdirectory(./chiavdf)

add_custom_target(${PROJECT_NAME}
# 编译C/C++
COMMAND cmake --build . -- -j4
# 编译go
COMMAND go build ${CMAKE_CURRENT_SOURCE_DIR}
)
