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
if [ "$TEST_CASE" -eq "0" ] || [ "$TEST_CASE" -eq "2" ]; then
  echo "Cleaning Data"
  ls -lhs $DATA_DIR
  rm -rf $DATA_DIR/*
fi

for ts in 4k 16k 64k 256k 1m 4m 16m 64m; do 
  LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior -o=${DATA_DIR}/test.bat -F -m -b=1g -t=${ts} -i 10 -w -r -d 5
  sleep 10
done

