#!/bin/bash
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
echo $SCRIPT_DIR
TEST_DIR=$(dirname $SCRIPT_DIR)
PROJECT_DIR=$(dirname $TEST_DIR)

DFPROFILER_SO=${PROJECT_DIR}/build/libdfprofiler.so

DATA_DIR=${PROJECT_DIR}/build/data

mkdir -p ${DATA_DIR} 
rm -rf ${DATA_DIR}/*
NUM_FILES=1
NUM_OPS=$((1024*1024))
TS=$((4*1024))
LD_PRELOAD=${DFPROFILER_SO} ${PROJECT_DIR}/build/tests/df_tracer_test ${NUM_FILES} ${NUM_OPS} ${TS} ${DATA_DIR} 1
