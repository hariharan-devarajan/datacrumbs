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

LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior -o=${DATA_DIR}/test.bat -F -m -b=16m -t=1m -i 10 -w -r -d 5


