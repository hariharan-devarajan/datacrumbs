

```bash
# 32 GB
# 0-> write
mpirun -np 1 --use-hwthread-cpus -x LD_PRELOAD=/home/cc/datacrumbs/build/libdatacrumbs.so /home/cc/datacrumbs/build/tests/df_tracer_test 1 1 34359738368 /home/cc/datacrumbs/build/data 0
```