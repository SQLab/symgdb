import struct
import os
import sys
from triton import *

# Import module from current directory
SYMBOLICFILE = os.path.abspath(os.path.expanduser(__file__))
sys.path.insert(0, os.path.dirname(SYMBOLICFILE))
from singleton import Singleton

EFLAGS = ['cf', 'pf', 'af', 'zf', 'sf', 'tf', 'if', 'df', 'of']

WORD = {'amd64': 4, 'i386': 2}
WORD_BITS = 16
POINTER_BYTE = {'amd64': 8, 'i386': 4}
REG_BITS = {'amd64': 64, 'i386': 32}
STRUCT_FORMAT = {'amd64': '<Q', 'i386': '<I'}
TRITON_ARCH = {'amd64': ARCH.X86_64, 'i386': ARCH.X86}
PC_REG = {'amd64': 'rip', 'i386': 'eip' }

class Arch(Singleton,object):
    def __init__(self):
        if(self._initialized):
            return
        self._initialized = True
        self.pointer_byte = POINTER_BYTE[GdbUtil().arch]
        self.struct_format = STRUCT_FORMAT[GdbUtil().arch]
        self.triton_arch = TRITON_ARCH[GdbUtil().arch]
        setArchitecture(self.triton_arch)
        self.pc_reg = getattr(REG,PC_REG[GdbUtil().arch].upper())
        self.pc = PC_REG[GdbUtil().arch]
        self.reg_bits = REG_BITS[GdbUtil().arch]

    def reset(self):
        self.__init__()


def parse_arg(arg):
    return map(lambda x: x.encode("ascii"), arg.split())


class GdbUtil(Singleton,object):
    def __init__(self):
        if(self._initialized):
            return
        self._initialized = True
        self.regs = self.get_regs()
        self.file = self.get_file()
        self.arch = self.get_arch()

    def reset(self):
        self.__init__()

    def get_file(self):
        """
        Get file from gdb
        """
        out = gdb.execute("info files", to_string=True)
        if out and '"' in out:
            p = re.compile(".*exec file:\s*`(.*)'")
            m = p.search(out)
            if m:
                result = m.group(1)
            else:  # stripped file, get symbol file
                p = re.compile("Symbols from \"([^\"]*)")
                m = p.search(out)
                if m:
                    result = m.group(1)
        return result

    def get_arch(self):
        filedata = open(self.file, "rb").read(0x800)
        # Linux binaries
        if filedata[0:4] == b"\x7FELF":
            # get file type
            fb = struct.unpack("H", filedata[0x12:0x14])[0]  # e_machine
            if fb == 0x3e:
                return "amd64"
            elif fb == 0x03:
                return "i386"
            else:
                raise Exception("binary type " + hex(fb) + " not supported")
        return None

    def get_argc(self):
        stack_start_address = self.get_stack_start_address()
        argc_raw = "".join(
            list(gdb.selected_inferior().read_memory(stack_start_address,
                                                     Arch().pointer_byte)))
        return struct.unpack(Arch().struct_format, argc_raw)[0]

    def get_argv_list(self):
        """
        Return argv list
        argv_list = [
            [argv[0] address, size],
            [argv[1] address, size]
        ]
        """
        argv_list = []
        argv_base = self.get_stack_start_address() + Arch().pointer_byte
        for i in range(self.get_argc()):
            pointer = argv_base + Arch().pointer_byte * i
            pointer_raw = "".join(list(gdb.selected_inferior().read_memory(pointer,Arch().pointer_byte)))
            address = struct.unpack(STRUCT_FORMAT[self.arch], pointer_raw)[0]
            size = 0
            while ord(list(gdb.selected_inferior().read_memory(address + size,1))[0]) != 0:
                size += 1
            argv_list.append((address, size))
        return argv_list

    def get_stack_start_address(self):
        out = gdb.execute("info proc all", to_string=True)
        line = out.splitlines()[-1]
        pattern = re.compile("(0x[0-9a-f]*)")
        matches = pattern.findall(line)
        return int(matches[0], 0)

    def get_main_frame_number(self):
        out = gdb.execute("backtrace", to_string=True)
        # #1  0x080484af in main ()
        pattern = re.compile("#([\d])\s+(0x[0-9a-f]*)\sin\s(\w+)")
        matches = pattern.findall(out)
        for (num, address, name) in matches:
            if name == "main":
                return num
        return None

    def getmemory(self, address, size):
        """
        Get memory content from gdb
        Args:
            - address: start address of memory
            - size: address length
        Returns:
            - list of memory content
        """
        return map(ord,
                   list(gdb.selected_inferior().read_memory(address, size)))

    def get_regs(self):
        """
        Get registers from gdb
        """
        out = gdb.execute("info registers", to_string=True).encode("ascii")
        regs = {}
        for line in out.splitlines():
            reg, reg_val = line.split()[0:2]
            regs[reg] = int(reg_val, 0)
        return regs

    def get_reg(self, reg):
        """
        Get register from gdb
        Args:
            - reg: register name
        Returns:
            - value of register
        """
        return self.regs[reg]

    def geteflag(self, eflag):
        """
        Get eflag register from gdb
        """
        EFLAGS = {}
        EFLAGS['cf'] = 1 << 0
        EFLAGS['pf'] = 1 << 2
        EFLAGS['af'] = 1 << 4
        EFLAGS['zf'] = 1 << 6
        EFLAGS['sf'] = 1 << 7
        EFLAGS['tf'] = 1 << 8
        EFLAGS['if'] = 1 << 9
        EFLAGS['df'] = 1 << 10
        EFLAGS['of'] = 1 << 11

        result = {}
        eflags = self.get_reg("eflags")
        for key, value in EFLAGS.iteritems():
            result[key] = bool(eflags & value)
        return result[eflag]

    def getvmmap(self):
        """
        Get virtual memory mappings from gdb
        """
        pid = int(gdb.selected_inferior().pid)
        maps = []
        mpath = "/proc/%s/maps" % pid
        #00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
        pattern = re.compile(
            "([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")

        out = open(mpath).read()

        matches = pattern.findall(out)
        if matches:
            for (start, end, perm, mapname) in matches:
                start = int(("0x%s" % start), 0)
                end = int(("0x%s" % end), 0)
                if mapname == "":
                    mapname = "mapped"
                maps += [(start, end, perm, mapname)]
        return maps

class Symbolic(Singleton, object):
    """
    Saved information about Symbolic execution
    """

    def __init__(self):
        if(self._initialized):
            return
        self._initialized = True
        self.debug = False
        self.symbolized_argc = False
        self.symbolized_argv = False
        self.symbolized_memory = []
        self.symbolized_registers = []
        self.registers = {}
        self.breakpoint = None
        self.target_address = None

    def check(self):
        if not self.target_address:
            return False
        return True

    def emulate(self, pc):
        while pc:
            # Fetch opcodes
            opcodes = getConcreteMemoryAreaValue(pc, 16)

            # Create the Triton instruction
            instruction = Instruction()
            instruction.setOpcodes(opcodes)
            instruction.setAddress(pc)

            # Process
            processing(instruction)
            #print(instruction)

            #if pc == 0x4005DC:
            if isRegisterSymbolized(Arch().pc_reg):
            #if instruction.getAddress() == 0x080484BC:
                pc_expr = getSymbolicExpressionFromId(getSymbolicRegisterId(Arch().pc_reg))
                pc_ast = ast.extract(Arch().reg_bits-1, 0, pc_expr.getAst())

                # Define constraint
                cstr = ast.assert_(ast.equal(pc_ast, ast.bv(self.target_address, Arch().reg_bits)))

                print('[+] Asking for a model, please wait...')
                model = getModel(cstr)
                if model:
                    for k, v in model.items():
                        value = v.getValue()
                        getSymbolicVariableFromId(k).setConcreteValue(value)
                        print('[+] Symbolic variable %02d = %02x (%c)' %
                              (k, value, chr(value)))
                    raw_input("Answer")
            # Next
            pc = buildSymbolicRegister(REG.EIP).evaluate()

    def set_breakpoint(self, address):
        self.breakpoint = address

    def set_target_address(self, address):
        self.target_address = address

    def set_arch(self):
        setArchitecture(Arch().triton_arch)

    def optimization(self):
        enableMode(MODE.ALIGNED_MEMORY, True)
        enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

    def load_segment(self, start, end):
        size = end - start
        print(hex(start),hex(end))
        setConcreteMemoryAreaValue(start, GdbUtil().getmemory(start, size))

    def load_binary(self):
        binary = Elf(GdbUtil().file)
        raw = binary.getRaw()

        phdrs = binary.getProgramHeaders()
        for phdr in phdrs:
            offset = phdr.getOffset()
            size = phdr.getFilesz()
            vaddr = phdr.getVaddr()
            print('[+] Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size))
            setConcreteMemoryAreaValue(vaddr, raw[offset:offset + size])

    def setregs(self):
        self.registers = GdbUtil().get_regs()
        print(self.registers)
        for reg, reg_val in self.registers.iteritems():
            print("Set %s: %s" % (str(reg), str(hex(reg_val))))
            setConcreteRegisterValue(
                Register(getattr(REG, reg.upper()), reg_val))

    def symbolize_argv(self):
        argv_list = GdbUtil().get_argv_list()
        address, size = argv_list[1]
        print(hex(address))
        print("symbolize memory: ", hex(address), size)
        for index in range(size):
            convertMemoryToSymbolicVariable(
                MemoryAccess(address + index, CPUSIZE.BYTE))

    def symbolize_memory(self):
        for address, size in self.symbolized_memory:
            print("symbolize memory: ", hex(address), size)
            for index in range(size):
                convertMemoryToSymbolicVariable(
                    MemoryAccess(address + index, CPUSIZE.BYTE))

    def symbolize_registers(self):
        for reg in self.symbolized_registers:
            print("symbolize reg: ", reg)
            convertRegisterToSymbolicVariable(
                Register(getattr(REG, reg.upper())))
    def load_stack(self):
        vmmap = GdbUtil().getvmmap()
        for start,end,permission,name in vmmap:
            if name == '[stack]':
                self.load_segment(start,end)

    def init(self):
        #resetEngines()
        if not self.check():
            return
        self.set_arch()
        #enableSymbolicEngine(True)
        self.optimization()
        self.load_binary()
        self.setregs()
        self.load_stack()

        # make Symbolic

        if self.symbolized_argv:
            self.symbolize_argv()
        self.symbolize_memory()
        self.symbolize_registers()

        raw_input("Press any key to start")
        self.emulate(self.registers[Arch().pc])


# Commands


class SymbolizeMemory(gdb.Command):
    def __init__(self):
        super(SymbolizeMemory, self).__init__("symbolize_memory",
                                              gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        Symbolic().symbolized_memory.append(
            map(lambda x: int(x, 0), parse_arg(arg)))


class SymbolizeRegister(gdb.Command):
    def __init__(self):
        super(SymbolizeRegister, self).__init__("symbolize_register",
                                                gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        Symbolic().symbolized_registers.append(parse_arg(arg))


class SymbolizeArgv(gdb.Command):
    def __init__(self):
        super(SymbolizeArgv, self).__init__("symbolize_argv", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        Symbolic().symbolized_argv = True
        print(Symbolic().symbolized_argv)
        print("Automatically symbolize argv")

class Target(gdb.Command):
    def __init__(self):
        super(Target, self).__init__("target", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = parse_arg(arg)
        Symbolic().target_address = int(args[0],0)

class Triton(gdb.Command):
    def __init__(self):
        super(Triton, self).__init__("triton", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        Symbolic().init()


class Test(gdb.Command):
    def __init__(self):
        super(Test, self).__init__("test", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        x = Symbolic()
        print(id(x))
        x = Symbolic()
        print(id(x))

        print(x.symbolized_argv)
        Symbolic().symbolized_argv=True
        print(Symbolic().symbolized_argv)
        print(Symbolic().symbolized_argv)

def breakpoint_handler(event):
    print("breakpoint reached")


#gdb.events.stop.connect(breakpoint_handler)

Triton()
SymbolizeMemory()
SymbolizeRegister()
SymbolizeArgv()
Target()
Test()


def needConcreteMemoryValue(mem):
    """
    if mem.hasConcreteValue():
        return
    """
    mem_addr = mem.getAddress()
    mem_size = mem.getSize()
    print("Need" + str(hex(mem_addr)) + ":" + str(mem_size))
    """
    try:
        print("Try to get memory value from triton")
        mem_val = getConcreteMemoryValue(MemoryAccess(mem_addr,mem_size))
    except Exception:
        print("Failed")
        pass
    """

    memory_list = map(
        ord, list(gdb.selected_inferior().read_memory(mem_addr, mem_size)))
    mem_val = int(to_hexstr(memory_view), 16)
    print("Memory from %s length %d: %s" % memory_list)
    #setConcreteMemoryValue(MemoryAccess(mem_addr,mem_size, mem_val))


def needConcreteRegisterValue(reg):
    """
    if reg.getConcreteValue():
        return
    """
    reg = reg.getName()
    if reg == "eip":
        return
    print("Need %s value" % reg)
    """
    try:
        print("Try to get register value from triton")
        reg_val = getConcreteRegisterValue(Register(getattr(REG, reg.upper())))
        print("Succeed %s value= %s" % (reg, str(hex(reg_val))))
    except Exception:
        print("Failed")
        pass
    """

    if reg in EFLAGS:
        reg = 'eflags'
        reg_val = GdbUtil().get_reg('eflags')
        reg_val = getConcreteRegisterValue(Register(getattr(REG, reg.upper())))
        print("Eflags:" + str(reg_val))
        return
    else:
        reg_val = GdbUtil().get_reg(reg)

    print("Got %s value: %s" % (reg, str(hex(reg_val))))
    #setConcreteRegisterValue(Register(getattr(REG, reg.upper()),reg_val))
