#!/bin/bash
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
echo $SCRIPT_DIR
TEST_DIR=$(dirname $SCRIPT_DIR)
PROJECT_DIR=$(dirname $TEST_DIR)
PARENT_DIR=$(dirname $PROJECT_DIR)
IOR_INSTALL_DIR=${PARENT_DIR}/ior/install
DATACRUMBS_SO=${PROJECT_DIR}/build/libdatacrumbs.so

DATA_DIR=${PROJECT_DIR}/build/data
mkdir -p $DATA_DIR
rm -rf $DATA_DIR/*
for ts in 4k 16k 64k 256k 1m 4m 16m 64m; do 
  configuration="-o=${DATA_DIR}/test.bat -F -m -b=1g -i 10 -d 5 -t=${ts}"
  LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
  sleep 10
  LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
  sleep 10
  rm -rf $DATA_DIR/*
done

