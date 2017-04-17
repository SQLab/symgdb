#!/bin/bash
sudo apt-get install -y build-essential libcap-dev
# Install z3
if [ ! $(python -c "import z3") ]; then
  git clone https://github.com/Z3Prover/z3
  cd z3
  python scripts/mk_make.py --python
  cd build
  make
  sudo make -j $(grep processor < /proc/cpuinfo | wc -l) install
  cd ../..
fi

# Install triton
if [ ! $(python -c "import triton") ]; then
  git clone https://github.com/JonathanSalwan/Triton.git
  cd Triton
  mkdir build
  cd build
  cmake ..
  sudo make -j $(grep processor < /proc/cpuinfo | wc -l) install
  cd ../..
fi
sudo pip install --upgrade -r requirements.txt
./build.sh
