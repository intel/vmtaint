Quick setup:

```
sudo apt-get install git cmake clang libboost-dev libtool automake autoconf pkg-config libipt-dev
git submodule update --init Triton
cd Triton
mkdir build
cd build
cmake ..
sudo make install
cd ../..
autoreconf -vif
./configure
make
```
