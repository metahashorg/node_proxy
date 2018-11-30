# MetaHash network Proxy

This repository contains the Proxy Node source code written in C++. There are two internal libraries: [libmicrohttpd2](https://github.com/metahashorg/libmicrohttpd2) and [libmhsupport](https://github.com/metahashorg/libmhsupport) used in this code. 

## Requirements
```shell
cmake > 3.8
gcc > 8.0
libevent 2.1.8
```

## Build

Please follow these steps to build and run Proxy on Ubuntu 14.04 x64:
1. Preparation
```shell
add-apt-repository ppa:ubuntu-toolchain-r/test
apt update

apt install gcc-8 g++-8 liburiparser-dev libssl-dev libevent-dev git libevent-2.0-5 automake libtool texinfo make
    
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 60 --slave /usr/bin/g++ g++ /usr/bin/g++-8
update-alternatives --config gcc
```
2. Get and compile latest cmake
```shell
cd /tmp
wget https://github.com/Kitware/CMake/releases/download/v3.13.0/cmake-3.13.0.tar.gz
cd cmake-3.13.0
./bootstrap
./configure
make
sudo make install 
```
3. Get and compile libevent
```shell
cd /tmp
wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
tar zxfv libevent-2.1.8-stable.tar.gz
cd libevent-2.1.8-stable
./configure
make
sudo make install
```
4. Get and compile libmicrohttpd2

Please note: you must use this libmicrohttpd2 library, because the original libmicrohttpd library has no all functions available which are necessary for running Proxy.
```shell
cd /tmp
git clone https://github.com/metahashorg/libmicrohttpd2
cd libmicrohttpd2
./bootstrap
./configure
make
sudo make install
```
5. Get and compile libmhsupport
```shell
cd /tmp
git clone https://github.com/metahashorg/libmhsupport
cd libmhsupport/build
./build.sh
sudo make install
```
6. Build Proxy Node
```shell
git clone https://github.com/metahashorg/node_proxy
cd node_proxy/build
./build.sh
```

You are also welcome to download a compiled executable for ubuntu 14/16/18 in repository releases.
