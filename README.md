# freesocks

# Introduction

[freesocks](https://github.com/RichieMay/freesocks) is a lightweight secured SOCKS5
proxy for me.

# Installation

## Build from source

### Installation of basic build dependencies

boost version <= 1.65

If you are using CentOS 6.x, you need to install these prequirement to build from source code:
```bash
yum install epel-release -y
yum install unzip wget cmake gcc gcc-c++ boost148-devel boost148-static -y
```

If you are using CentOS 7.x：
```bash
yum install epel-release -y
yum install unzip wget cmake gcc gcc-c++ boost-devel boost-static -y
```

If you are using Mac OS,
```bash
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install wget boost@1.60 cmake gcc
```

### Get the latest source code

To get the latest source code, you should also update the submodules as following:

```bash
wget -O freesocks-master.zip https://github.com/RichieMay/freesocks/archive/master.zip
unzip freesocks-master.zip
```

### Compile 

If you are using CentOS 6.x：
```bash
cd freesocks-master
mkdir build && cd build
cmake .. -DBOOST_INCLUDEDIR=/usr/include/boost148 -DBOOST_LIBRARYDIR=/usr/lib/boost148
make
```

If you are using CentOS 7.x：
```bash
cd freesocks-master
mkdir build && cd build
cmake ..
make
```

If you are using Mac OS:
```bash
cd freesocks-master
mkdir build && cd build
cmake .. -DBOOST_ROOT=/usr/local/Cellar/boost\@1.60/1.60.0
make
```
