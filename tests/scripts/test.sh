#!/bin/bash
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
echo $SCRIPT_DIR
TEST_DIR=$(dirname $SCRIPT_DIR)
PROJECT_DIR=$(dirname $TEST_DIR)

DATACRUMBS_SO=${PROJECT_DIR}/build/libdatacrumbs.so

DATA_DIR=${PROJECT_DIR}/build/data
mkdir -p $DATA_DIR
NUM_FILES=1
NUM_OPS=$((1024*8))
TEST_CASE=1 #write=0 read=1 both=2
if [ "$TEST_CASE" -eq "0" ] || [ "$TEST_CASE" -eq "2" ]; then
  echo "Cleaning Data"
  ls -lhs $DATA_DIR
  rm -rf $DATA_DIR/*
fi

for TSKB in 4096; #1 4 16 64 256 1024 4096 16384 65536 262144
do
  TS=$((TSKB * 1024))
  echo "Clean Cache"
  sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
  cmd="mpirun -np 1 --use-hwthread-cpus -x LD_PRELOAD=${DATACRUMBS_SO} ${PROJECT_DIR}/build/tests/df_tracer_test ${NUM_FILES} ${NUM_OPS} ${TS} ${DATA_DIR} ${TEST_CASE}"
  echo $cmd
  $cmd
  sleep 5
done


