# Local Installation
Installing and using DtaCrumbs on your local machine.
```

```
### Git Root
```bash
git clone https://github.com/hariharan-devarajan/datacrumbs
cd datacrumbs
sudo su
export DATACRUMBS_ROOT=$PWD
export DATACRUMBS_ROOT=$PWD
```


## Local Environment Dependency Installation & Setup
- OS:
```
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.3 LTS
Release:        22.04
Codename:       jammy
```
- Kernel: `6.5.0-44-generic`
- BCC > v0.30.0
```bash


sudo su
apt-get update
apt-get install -y apt-transport-https ca-certificates curl clang llvm jq
apt-get install -y libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make 
apt-get install -y linux-tools-common linux-tools-$(uname -r) 
apt-get install -y bpfcc-tools

git clone https://github.com/iovisor/bcc
cd bcc
export BCC_ROOT=$PWD
mkdir build
pushd build
cmake ..
make -j2
make install -j
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
make install
popd
popd
sudo cp -r $BCC_ROOT/build/src/python/bcc-python3/bcc/* /usr/lib/python3/dist-packages/bcc/
exit # exit out sudo
```

- cmake 3.22.1
```bash
sudo apt-get install cmake
```
- Python 3.10.10
  - hydra-core>=1.2.0
```bash
# For profiler
python3 -m venv ./venv
source venv/bin/activate
cd $DATACRUMBS_ROOT
pip install -r requirements.txt

# For analysis
cd $DATACRUMBS_ROOT/analysis
pip install -r requirements.txt
```

## Profiling
1. Start profiler
```bash
sudo su
cd $DATACRUMBS_ROOT
python3 datacrumbs/main.py # takes few minutes to attach probes
```
Once see the below output, you can start to run your program with another process:
```log
2024-08-07 11:15:52,941 [INFO]: 17784 functions matched in $DATACRUMBS_ROOT/datacrumbs/dfbcc/dfbcc.py:65
2024-08-07 11:15:52,941 [INFO]: Ready to run code in $DATACRUMBS_ROOT/datacrumbs/dfbcc/dfbcc.py:184
2024-08-07 11:15:52,949 [DEBUG]: sleeping for 5.0 secs with last ts -1 in $DATACRUMBS_ROOT/datacrumbs/dfbcc/dfbcc.py:205
...
```
2. Start your program
Profiler must be running when you start your program, below is using the test program as example:
```bash
bash $DATACRUMBS_ROOT/tests/scripts/write.sh
```
A file named `profile.pfw` will be generated.
```bash
head -n 5 $DATACRUMBS_ROOT/profile.pfw
[
{"pid": 39294, "tid": 39294, "name": "is_file_shm_hugepages [kernel]", "cat": "vfs", "ph": "C", "ts": 0, "args": {"hostname": "myname", "fname": null, "freq": 81, "time": 0.000272729, "size_sum": null}}
{"pid": 39294, "tid": 39294, "name": "free_unref_page_commit [kernel]", "cat": "os_cache", "ph": "C", "ts": 0, "args": {"hostname": "myname", "fname": null, "freq": 15, "time": 0.000126361, "size_sum": null}}
{"pid": 39295, "tid": 39295, "name": "close", "cat": "sys", "ph": "C", "ts": 0, "args": {"hostname": "myname", "fname": "sys/bus/cpu/devices/cpu10/online", "freq": 1, "time": 5.69e-06, "size_sum": null}}
{"pid": 39295, "tid": 39295, "name": "close", "cat": "sys", "ph": "C", "ts": 0, "args": {"hostname": "myname", "fname": "sys/bus/cpu/devices/cpu13/online", "freq": 1, "time": 5.77e-06, "size_sum": null}}
```
If the file is ziped, view with gzip:
```bash
gzip -cd $DATACRUMBS_ROOT/profile.pfw.gz | head -n 5
```