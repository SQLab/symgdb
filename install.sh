#!/bin/bash
sudo apt-get install -y build-essential libcap-dev
echo "source ~/gdb-web/gdb-web.py" >> ~/.gdbinit
sudo pip install --upgrade -r requirements.txt
