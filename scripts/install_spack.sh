#!/bin/bash
sudo pip install -r requirements.txt
sudo apt-get update
sudo apt-get install -y hwloc libtool openssl libssl-dev gfortran gcc g++
sudo chmod 777 /opt -R
SPACK_ROOT=/opt/spack
git clone https://github.com/spack/spack.git ${SPACK_ROOT}
source ${SPACK_ROOT}/share/spack/setup-env.sh 
spack external find
spack compiler find
spack install -j64 openmpi@5.0.5%gcc@11.4.0 hdf5@1.14.5%gcc@11.4.0
export HDF5_DIR=$(spack location -i hdf5@1.14.5%gcc@11.4.0)
export OPENMPI_DIR=$(spack location -i openmpi@5.0.5%gcc@11.4.0)
echo "Set HDF5 to ${HDF5_DIR}"
echo "Set OPENMPI to ${OPENMPI_DIR}"
IOR_DIR=/opt/ior
git clone git@github.com:hpc/ior.git ${IOR_DIR}
cd $IOR_DIR
./bootstrap
./configure --with-hdf5 --prefix=$PWD/install CFLAGS="-I${HDF5_DIR}/include -L${HDF5_DIR}/lib" CPPFLAGS="-I${HDF5_DIR}/include -L${HDF5_DIR}/lib"
make install
cd -
