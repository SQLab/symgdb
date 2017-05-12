# gdb symbolic

gdb-symbolic - symbolic execution extention for gdb

# Installation

**Warning!!! Installation script will overwrite your gdb**

**Due to python3 not supported for triton yet**

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
