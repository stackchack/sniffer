cmake_minimum_required(VERSION 3.2)

project(tests)

add_executable(tests "${CMAKE_SOURCE_DIR}/tests.cpp" 
"${CMAKE_SOURCE_DIR}/../sniffer/includes.cpp"
)

target_link_libraries(tests glog pcap gtest)
