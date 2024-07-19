#!/bin/bash

sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl clang llvm jq
sudo apt-get install -y libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make 
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r) linux-headers-$(uname -r)
sudo apt-get install -y bpfcc-tools
sudo apt-get install -y python3-pip python3.9-venv
# Install bcc
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
    libllvm12 llvm-12-dev libclang-12-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
    liblzma-dev libdebuginfod-dev arping netperf iperf
sudo apt install -y clangd

echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 428D7C01 C8CAB6595FDFF622

sudo apt-get update

sudo apt-get install openmpi-bin-dbgsym openmpi-doc libopenmpi-dev 

git clone https://github.com/iovisor/bcc.git ~/bcc
mkdir bcc/build
pushd bcc/build
cmake ..
make -j
sudo make install -j
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
popd
sudo cp -r ~/bcc/build/src/python/bcc-python3/bcc/* /usr/lib/python3/dist-packages/bcc/