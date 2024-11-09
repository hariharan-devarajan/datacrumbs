#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_DIR=$(dirname  $SCRIPT_DIR)
export PYTHONPATH=$PROJECT_DIR
SPACK_ROOT=/opt/spack
source ${SPACK_ROOT}/share/spack/setup-env.sh
spack install hdf5@1.14.5 openmpi@5.0.5
HDF5_DIR=$(spack location -i hdf5)
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$HDF5_DIR/lib