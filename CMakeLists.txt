# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.8)

# 项目信息
project (freesocks)

# 设置C/C+编译器
#set(CMAKE_C_COMPILER mipsel-mt7621-linux-gcc)
#set(CMAKE_CXX_COMPILER mipsel-mt7621-linux-g++)

# 检查boost是否存在
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package( Boost REQUIRED COMPONENTS regex thread system chrono date_time program_options)
if(Boost_FOUND)
	include_directories(${Boost_INCLUDE_DIRS})
endif()

#禁用C11
add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)

# 添加动态函数库/线程库
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ldl")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

# 查找指定目录下的所有源文件
aux_source_directory(source SRCS)

# 指定生成目标
add_executable(freesocks ${SRCS})

# 链接boost库
target_link_libraries(freesocks ${Boost_LIBRARIES})
