# Install dependencies:

```
sudo apt-get install git cmake clang libboost-dev libtool automake autoconf pkg-config libipt-dev
```

# Install Triton:

```
git submodule update --init triton
cd triton
mkdir build
cd build
cmake ..
sudo make install
cd ../..
```

# Install LibVMI:

```
git submodule update --init libvmi
cd libvmi
autoreconf -vif
./configure --disable-kvm
make
sudo make install
cd ..
```

# Build vmtaint:

```
autoreconf -vif
./configure
make
```
