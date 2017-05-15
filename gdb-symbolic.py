import os
import sys
import click
import struct
from termcolor import colored, cprint
from triton import *

# Import module from current directory
SYMBOLICFILE = os.path.abspath(os.path.expanduser(__file__))
sys.path.insert(0, os.path.dirname(SYMBOLICFILE))
from singleton import Singleton


def parse_arg(arg):
    return map(lambda x: x.encode("ascii"), arg.split())


class Arch(Singleton, object):
    def __init__(self):
        if (self._initialized):
            return
        pointer_byte = {'amd64': 8, 'i386': 4}
        reg_bits = {'amd64': 64, 'i386': 32}
        struct_format = {'amd64': '<Q', 'i386': '<I'}
        triton_arch = {'amd64': ARCH.X86_64, 'i386': ARCH.X86}
        pc_reg = {'amd64': 'rip', 'i386': 'eip'}
        self.arch = self.get_arch()
        self._initialized = True
        self.pointer_byte = pointer_byte[self.arch]
        self.reg_bits = reg_bits[self.arch]
        self.struct_format = struct_format[self.arch]
        self.triton_arch = triton_arch[self.arch]
        setArchitecture(self.triton_arch)
        self.triton_pc_reg = getattr(REG, pc_reg[self.arch].upper())
        self.pc_reg = pc_reg[self.arch]

    def get_arch(self):
        filedata = open(GdbUtil().file, "rb").read(0x800)
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


class GdbUtil(Singleton, object):
    def __init__(self):
        if (self._initialized):
            return
        self._initialized = True
        self.file = self.get_file()
        self.regs = self.get_regs()

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
            pointer_raw = "".join(
                list(gdb.selected_inferior().read_memory(pointer,
                                                         Arch().pointer_byte)))
            address = struct.unpack(Arch().struct_format, pointer_raw)[0]
            size = 0
            while ord(
                    list(gdb.selected_inferior().read_memory(address + size,
                                                             1))[0]) != 0:
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

    def get_memory(self, address, size):
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

    def get_reg(self, reg):
        """
        Get register from gdb
        Args:
            - reg: register name
        Returns:
            - value of register
        """
        return self.regs[reg]

    def get_eflag(self, eflag):
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

    def get_vmmap(self):
        """
        Get virtual memory mappings from gdb
        """
        pid = int(gdb.selected_inferior().pid)
        maps = []
        mpath = "/proc/%s/maps" % pid
        # 00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
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
        if (self._initialized):
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

    def log(self, s):
        if self.debug:
            print(s)

    def emulate(self, pc):
        while pc:
            # Fetch opcodes
            opcodes = getConcreteMemoryAreaValue(pc, 16)

            # Create the Triton instruction
            instruction = Instruction()
            instruction.setOpcodes(opcodes)
            instruction.setAddress(pc)

            # Process
            if (not processing(instruction)):
                print("Current opcode is not supported.")
            self.log(instruction)

            if isRegisterSymbolized(Arch().triton_pc_reg):
                #if instruction.getAddress() == 0x080484BC:
                pc_expr = getSymbolicExpressionFromId(
                    getSymbolicRegisterId(Arch().triton_pc_reg))
                pc_ast = ast.extract(Arch().reg_bits - 1, 0, pc_expr.getAst())

                # Define constraint
                cstr = ast.assert_(
                    ast.equal(pc_ast,
                              ast.bv(self.target_address, Arch().reg_bits)))

                model = getModel(cstr)
                if model:
                    cprint('Got answer!!!', 'green')
                    for sym_id, sym_model in model.items():
                        value = sym_model.getValue()
                        getSymbolicVariableFromId(sym_id).setConcreteValue(
                            value)
                        cprint('Symbolic variable %02d = %02x (%c)' %
                               (sym_id, value, chr(value)), 'green')
                    if click.confirm('Inject back to gdb?', default=True):
                        self.inject_to_gdb()
                    return True
            # Next
            pc = buildSymbolicRegister(REG.EIP).evaluate()

    def inject_to_gdb(self):
        for address, size in self.symbolized_memory:
            self.log("Memory updated: %s-%s" %
                     (hex(address), hex(address + size)))
            for index in range(size):
                memory = chr(
                    getSymbolicMemoryValue(
                        MemoryAccess(address + index, CPUSIZE.BYTE)))
                gdb.selected_inferior().write_memory(address + index, memory,
                                                     CPUSIZE.BYTE)

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
        setConcreteMemoryAreaValue(start, GdbUtil().get_memory(start, size))

    def load_binary(self):
        binary = Elf(GdbUtil().file)
        raw = binary.getRaw()

        phdrs = binary.getProgramHeaders()
        for phdr in phdrs:
            offset = phdr.getOffset()
            size = phdr.getFilesz()
            vaddr = phdr.getVaddr()
            self.log('[+] Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size))
            setConcreteMemoryAreaValue(vaddr, raw[offset:offset + size])

    def set_regs(self):
        self.registers = GdbUtil().get_regs()
        for reg, reg_val in self.registers.iteritems():
            self.log("Set %s: %s" % (str(reg), str(hex(reg_val))))
            setConcreteRegisterValue(
                Register(getattr(REG, reg.upper()), reg_val))

    def symbolize_argv(self):
        argv_list = GdbUtil().get_argv_list()
        address, size = argv_list[1]
        if [address, size] not in self.symbolized_memory:
            self.symbolized_memory.append([address, size])

    def symbolize_memory(self):
        for address, size in self.symbolized_memory:
            self.log("Symbolize memory: %s-%s" %
                     (hex(address), hex(address + size)))
            for index in range(size):
                convertMemoryToSymbolicVariable(
                    MemoryAccess(address + index, CPUSIZE.BYTE))

    def symbolize_registers(self):
        for reg in self.symbolized_registers:
            self.log("Symbolize register: %s" % reg)
            convertRegisterToSymbolicVariable(
                Register(getattr(REG, reg.upper())))

    def load_stack(self):
        vmmap = GdbUtil().get_vmmap()
        for start, end, permission, name in vmmap:
            if name == '[stack]':
                self.load_segment(start, end)
            #print(hex(start),hex(end),permission,name)
            """
            if name.endswith('so'):
                if 'r' in permission:
                    self.load_segment(start,end)
            elif 'w' in permission and name != "mapped":
                print(name)
                self.load_segment(start,end)
            """

    def run(self):
        #resetEngines()
        if not self.check():
            return
        self.set_arch()
        #enableSymbolicEngine(True)
        self.optimization()
        self.load_binary()
        self.set_regs()
        self.load_stack()

        # make Symbolic

        if self.symbolized_argv:
            self.symbolize_argv()
        self.symbolize_memory()
        self.symbolize_registers()

        #raw_input("Press any key to start")
        if not self.emulate(self.registers[Arch().pc_reg]):
            print(cprint("No answer is found!!!", 'red'))


# Commands


class Symbolize(gdb.Command):
    def __init__(self):
        super(Symbolize, self).__init__("symbolize", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = parse_arg(arg)
        if args[0] == 'argv':
            cprint("Automatically symbolize argv", 'green')
            Symbolic().symbolized_argv = True
        elif args[0] == 'memory' and len(args) == 3:
            address, size = map(lambda x: int(x, 0), args[1:])
            cprint("Set symbolized memory %s-%s" %
                   (hex(address), hex(address + size)), 'green')
            Symbolic().symbolized_memory.append([address, size])
        elif args[0] == 'register':
            Symbolic().symbolized_registers.append(args[1])

    def complete(self, text, word):
        symbolize_list = ['argv', 'memory', 'register']
        completion = []
        if text != "":
            for s in symbolize_list:
                if text in s:
                    completion.append(s)
        else:
            completion = symbolize_list
        return completion


class Target(gdb.Command):
    def __init__(self):
        super(Target, self).__init__("target", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = parse_arg(arg)
        if len(args) == 1:
            target_address = int(args[0], 0)
            cprint("Set target address = %s" % hex(target_address), 'green')
            Symbolic().target_address = target_address


class Triton(gdb.Command):
    def __init__(self):
        super(Triton, self).__init__("triton", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        Symbolic().run()


class Debug(gdb.Command):
    def __init__(self):
        super(Debug, self).__init__("debug", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = parse_arg(arg)
        if args[0] == 'symbolic':
            Symbolic().debug = True
        elif args[0] == 'gdb':
            GdbUtil().debug = True
        else:
            Symbolic().debug = True
            GdbUtil().debug = True

    def complete(self, text, word):
        debug_list = ['symbolic', 'gdb']
        completion = []
        if text != "":
            for s in debug_list:
                if text in s:
                    completion.append(s)
        else:
            completion = debug_list
        return completion


class Reset(gdb.Command):
    def __init__(self):
        super(Reset, self).__init__("reset", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        Symbolic().reset()

    def complete(self, text, word):
        reset_list = ['symbolic']
        completion = []
        if text != "":
            for s in reset_list:
                if text in s:
                    completion.append(s)
        else:
            completion = reset_list
        return completion


def breakpoint_handler(event):
    GdbUtil().reset()
    Arch().reset()


gdb.events.stop.connect(breakpoint_handler)

Triton()
Symbolize()
Target()
Debug()
Reset()
