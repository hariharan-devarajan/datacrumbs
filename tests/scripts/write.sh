#!/bin/bash
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
echo $SCRIPT_DIR
TEST_DIR=$(dirname $SCRIPT_DIR)
PROJECT_DIR=$(dirname $TEST_DIR)

DATACRUMBS_SO=${PROJECT_DIR}/build/libdatacrumbs.so

DATA_DIR=${PROJECT_DIR}/build/data

mkdir -p ${DATA_DIR} 
rm -rf ${DATA_DIR}/*
NUM_FILES=1
NUM_OPS=$((1024*2))
TS=$((4*1024*1024))
TEST_CASE=0 #write=0 read=1 both=2
mpirun -np 12 --use-hwthread-cpus -x LD_PRELOAD=${DATACRUMBS_SO} ${PROJECT_DIR}/build/tests/df_tracer_test ${NUM_FILES} ${NUM_OPS} ${TS} ${DATA_DIR} ${TEST_CASE}
