# freesocks

# Introduction

[freesocks](https://github.com/RichieMay/freesocks) is a lightweight secured SOCKS5
proxy for me.

# Installation

## Build from source with centos

### Installation of basic build dependencies

If you are using CentOS 6.x, you need to install these prequirement to build from source code:
```bash
yum install epel-release -y
yum install unzip wget cmake gcc gcc-c++ boost148-devel -y
```

### Get the latest source code

To get the latest source code, you should also update the submodules as following:

```bash
wget -O freesocks-master.zip https://github.com/RichieMay/freesocks/archive/master.zip
unzip freesocks-master.zip
```

### Compile 

```bash
cd freesocks-master
mkdir build && cd build
cmake .. -DBOOST_INCLUDEDIR=/usr/include/boost148 -DBOOST_LIBRARYDIR=/usr/lib/boost148
```
