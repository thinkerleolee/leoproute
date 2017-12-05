cmake_minimum_required(VERSION 3.8)
project(leoproute)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp Ping.cpp Ping.h IcmpTool.cpp IcmpTool.h cmake-build-debug/IpTool.cpp cmake-build-debug/IpTool.h Traceroute.cpp Traceroute.h)
add_executable(leoproute ${SOURCE_FILES})