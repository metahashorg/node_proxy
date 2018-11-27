# Node Proxy

This repository contains the Node Proxy source code written in C++.  There are two internal libraries: [libmicrohttpd2](https://github.com/metahashorg/libmicrohttpd2) and [libmhsupport](https://github.com/metahashorg/libmhsupport) used in this code. 

## Build

Please follow these steps to build and run Proxy on Ubuntu successfully:
```shell
cmake > 3.8
    gcc > 8.0
    libevent 2.1.8

    add-apt-repository ppa:ubuntu-toolchain-r/test
    apt update
    apt install gcc-8 g++-8 liburiparser-dev libssl-dev libevent-dev git libevent-2.0-5 automake libtool texinfo make
    
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 60 --slave /usr/bin/g++ g++ /usr/bin/g++-8
    update-alternatives --config gcc    


    get and compile latest cmake

        wget https://github.com/Kitware/CMake/releases/download/v3.13.0/cmake-3.13.0.tar.gz
        cd cmake-3.13.0
        ./bootstrap
        ./configure
        make
        make install 

    get and compile libevent

        wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
        tar zxfv libevent-2.1.8-stable.tar.gz
        cd libevent-2.1.8-stable
        ./configure
          make
          make install


    cd /tmp
        git clone https://github.com/metahashorg/libmicrohttpd2
        cd libmicrohttpd2
        ./bootstrap
        ./configure
        make
        make install

    cd /tmp
        git clone https://github.com/metahashorg/libmhsupport
        cd libmhsupport/build
        mkdir build
        cd build
        cmake -DCMAKE_INSTALL_PREFIX=`readlink -f $INSTALL` -DCMAKE_BUILD_TYPE=Release  ..
        make --jobs=`nproc`
        make install

        git clone https://github.com/metahashorg/node_proxy
        cd proxy_prep/build
        ./build.sh
```
