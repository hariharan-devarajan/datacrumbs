

```bash
# 32 GB
# 1-> read
Clean Cache
mpirun -np 1 --use-hwthread-cpus -x LD_PRELOAD=/home/cc/datacrumbs/build/libdatacrumbs.so /home/cc/datacrumbs/build/tests/df_tracer_test 1 1 34359738368 /home/cc/datacrumbs/build/data 1
1,1,1,0,0.004487,0.000025,0.000000,0.000023
```