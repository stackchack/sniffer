cmake_minimum_required(VERSION 3.2)

project(sniffer)

add_executable(sniffer "${CMAKE_SOURCE_DIR}/main.cpp" 
"${CMAKE_SOURCE_DIR}/includes.cpp"
)

target_link_libraries(sniffer glog pcap)
