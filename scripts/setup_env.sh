#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_DIR=$(dirname  $SCRIPT_DIR)
export PYTHONPATH=$PROJECT_DIR
ulimit -n 1048576
export BCC_PROBE_LIMIT=1048576
SPACK_ROOT=/opt/spack
source ${SPACK_ROOT}/share/spack/setup-env.sh
spack load openmpi@5.0.5%gcc@11.4.0 hdf5@1.14.5%gcc@11.4.0
export HDF5_DIR=$(spack location -i hdf5@1.14.5%gcc@11.4.0)
export OPENMPI_DIR=$(spack location -i openmpi@5.0.5%gcc@11.4.0)
echo "Set HDF5 to ${HDF5_DIR}"
echo "Set OPENMPI to ${OPENMPI_DIR}"