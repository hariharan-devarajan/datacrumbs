#!/bin/bash
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
echo $SCRIPT_DIR
TEST_DIR=$(dirname $SCRIPT_DIR)
PROJECT_DIR=$(dirname $TEST_DIR)
PARENT_DIR=$(dirname $PROJECT_DIR)
IOR_INSTALL_DIR=${PARENT_DIR}/ior/install
DATACRUMBS_SO=${PROJECT_DIR}/build/libdatacrumbs.so

DATA_DIR=${PROJECT_DIR}/build/data
DROP_CACHES=1
mkdir -p $DATA_DIR
rm -rf $DATA_DIR/*
BLOCK=1g
# for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#   configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts}"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#   sleep 10
#   if [ "$DROP_CACHES" -eq "1" ];
#   then
#     echo "Clean Cache"
#     sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#   fi
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#   sleep 10
#   rm -rf $DATA_DIR/*
# done

# for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#   configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -O useO_DIRECT=1"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#   sleep 10
#   if [ "$DROP_CACHES" -eq "1" ];
#   then
#     echo "Clean Cache"
#     sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#   fi
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#   sleep 10
#   rm -rf $DATA_DIR/*
# done

# for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#   configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -e -Y"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#   sleep 10
#   if [ "$DROP_CACHES" -eq "1" ];
#   then
#     echo "Clean Cache"
#     sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#   fi
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#   sleep 10
#   rm -rf $DATA_DIR/*
# done

# for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#   configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -P"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#   sleep 10
#   if [ "$DROP_CACHES" -eq "1" ];
#   then
#     echo "Clean Cache"
#     sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#   fi
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#   sleep 10
#   rm -rf $DATA_DIR/*
# done

# for DROP_CACHES in 0 1; do
#   for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#     configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -a MPIIO"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#     LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#     sleep 10
#     if [ "$DROP_CACHES" -eq "1" ];
#     then
#       echo "Clean Cache"
#       sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#     fi
#     echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#     LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#     sleep 10
#     rm -rf $DATA_DIR/*
#   done
# done

# for DROP_CACHES in 0 1; do
#   for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#     configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -a MPIIO -c"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#     LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#     sleep 10
#     if [ "$DROP_CACHES" -eq "1" ];
#     then
#       echo "Clean Cache"
#       sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#     fi
#     echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#     LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#     sleep 10
#     rm -rf $DATA_DIR/*
#   done
# done

for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
  configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -Z -z"
  echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
  LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
  sleep 10
  if [ "$DROP_CACHES" -eq "1" ];
  then
    echo "Clean Cache"
    sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
  fi
  echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
  LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
  sleep 10
  rm -rf $DATA_DIR/*
done

# for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#   configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -a HDF5"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#   sleep 10
#   if [ "$DROP_CACHES" -eq "1" ];
#   then
#     echo "Clean Cache"
#     sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#   fi
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#   sleep 10
#   rm -rf $DATA_DIR/*
# done

# for ts in 256k; do # 4k 16k 64k 256k 1m 4m 16m 64m
#   configuration="-o=${DATA_DIR}/test.bat-${ts} -F -m -b=${BLOCK} -i 10 -d 10 -t=${ts} -a HDF5 -c"
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -w -k
#   sleep 10
#   if [ "$DROP_CACHES" -eq "1" ];
#   then
#     echo "Clean Cache"
#     sudo sh -c "/usr/bin/echo 3 > /proc/sys/vm/drop_caches"
#   fi
#   echo "Running ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r"
#   LD_PRELOAD=$DATACRUMBS_SO ${IOR_INSTALL_DIR}/bin/ior ${configuration} -r
#   sleep 10
#   rm -rf $DATA_DIR/*
# done