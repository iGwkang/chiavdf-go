
https://github.com/Chia-Network/chiavdf go bindings

### Usage:

Compiling chiavdf requires cmake, boost and GMP/MPIR.
```
sudo apt-get install m4
sudo apt-get install libgmp-dev
sudo apt-get install libboost-all-dev
```

- linux build
```
mkdir build && cd build
cmake ..
cmake --build . --target chiavdf-go
```
