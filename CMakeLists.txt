cmake_minimum_required(VERSION 3.15)
project(FileSyncTool)

set(CMAKE_CXX_STANDARD 17)

# 设置vcpkg
if(CMAKE_HOST_WIN32)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

# 子目录
add_subdirectory(src)
add_subdirectory(examples)