#!/bin/bash
sudo apt-get install -y build-essential libcap-dev cmake libboost-all-dev libcapstone-dev

# Install z3
python2 -c "import z3"
NOT_INSTALLED=$?
if [ $NOT_INSTALLED == 1 ]
then
  git clone https://github.com/Z3Prover/z3
  cd z3
  python scripts/mk_make.py --python
  cd build
  make
  sudo make -j $(grep processor < /proc/cpuinfo | wc -l) install
  cd ../..
fi

# Install triton
python2 -c "import triton"
NOT_INSTALLED=$?
if [ $NOT_INSTALLED == 1 ]
then
  git clone https://github.com/JonathanSalwan/Triton.git
  cd Triton
  mkdir build
  cd build
  cmake ..
  sudo make -j $(grep processor < /proc/cpuinfo | wc -l) install
  cd ../..
fi

# Install python modules
if [ !$(which pip2) ]; then
  sudo apt install python-pip
fi
sudo pip2 install --upgrade -r requirements.txt

# Build gdb
./build.sh
