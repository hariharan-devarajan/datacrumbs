#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_DIR=$(dirname  $SCRIPT_DIR)
export PYTHONPATH=$PROJECT_DIR
ulimit -n 1048576
export BCC_PROBE_LIMIT=1048576
SPACK_ROOT=/opt/spack
source ${SPACK_ROOT}/share/spack/setup-env.sh
# spack install hdf5@1.14.5 openmpi@5.0.5