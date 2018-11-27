cmake_minimum_required(VERSION 3.8)

project (proxy)

find_package(MHSupport)
find_package(Threads)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(${PROJECT_NAME} src/main.cpp  src/open_ssl_decor.cpp  src/proxyserver.cpp  src/transaction.cpp)

target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(${PROJECT_NAME} mh_mhd)
target_link_libraries(${PROJECT_NAME} mh_xxhash)
target_link_libraries(${PROJECT_NAME} mh_libevent)
target_link_libraries(${PROJECT_NAME} event)
target_link_libraries(${PROJECT_NAME} microhttpd)
target_link_libraries(${PROJECT_NAME} uriparser)
