# gdb symbolic

gdb-symbolic - symbolic execution extention for gdb

# Installation

**Warning!!! Installation script will overwrite your gdb**

**Due to python3 not supported for triton yet**

**Need to recompile gdb for python2**

```bash
./install.sh
echo "source ~/symgdb/symgdb.py" >> ~/.gdbinit
```

# Commands

| Command   | Options                | Functionality            |
|-----------|------------------------|--------------------------|
| symbolize | argv                   | Make symbolic            |
|           | memory [address][size] |                          |
| target    | address                | Set target address       |
| triton    |                        | Run symbolic execution   |
| answer    |                        | Print symbolic variables |
| debug     | symbolic gdb           | Show debug message       |

# Examples

You could combine with other gdb plugin, such as [peda](https://github.com/longld/peda).

## crackme hash 32

![crackme hash 32](./demo_videos/crackme-hash-32.gif)

## symbolize argv

![symbolize argv](./demo_videos/symbolize-argv.gif)

## crackme hash 64

![crackme hash 32](./demo_videos/crackme-hash-64.gif)

# Tests

```bash
./tests/run.sh
```

# Talk

- [Triton and Symbolic execution on GDB @ HITCON](https://hitcon.org/2017/CMT/slide-files/d2_s1_r0.pdf)
