# gdb symbolic

gdb-symbolic - symbolic execution extention for gdb

# Installation

**Warning!!! Install script will overwrite your gdb**

**Due to trition is not supported python3 yet**

**Need to recompile gdb for python2**

```bash
./install.sh
echo "source ~/gdb-symbolic/gdb-symbolic.py" >> ~/.gdbinit
```

# Commands

## symbolize

Make symbolic

### options

- argv
- memory [address] [size]
- register [register_name]

## target

Set target address

## triton

Run symbolic execution

# Tests

```bash
./tests/run.sh
```
