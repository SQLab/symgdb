from triton import *
import os
import sys
import struct
import time
sys.path.append(os.getcwd())
from utils import *
EFLAGS = ['cf', 'pf', 'af', 'zf', 'sf', 'tf', 'if', 'df', 'of']


class SYMBOLIC(object):
    def __init__(self):
        self.regs = {}

    def getfile(self):
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

    def setregs(self):
        print(self.regs)
        for reg, reg_val in self.regs.iteritems():
            print("Set %s: %s" % (str(reg), str(hex(reg_val))))
            setConcreteRegisterValue(
                Register(getattr(REG, reg.upper()), reg_val))

    def getregs(self):
        out = gdb.execute("info registers", to_string=True)
        for line in out.splitlines():
            reg, reg_val = line.split()[0:2]
            self.regs[reg] = to_int(reg_val)

    def getreg(self, reg):
        self.getregs()
        return self.regs[reg]

    def geteflag(self, eflag):
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
        eflags = self.getreg("eflags")
        for key, value in EFLAGS.iteritems():
            result[key] = bool(eflags & value)
        return result[eflag]

    def getvmmap(self):
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
                start = to_int("0x%s" % start)
                end = to_int("0x%s" % end)
                if mapname == "":
                    mapname = "mapped"
                maps += [(start, end, perm, mapname)]
        return maps


class ReadRegister(gdb.Command):
    def __init__(self):
        super(ReadRegister, self).__init__("readregister", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global registers
        args = arg.split()
        args[0] = args[0].encode('ascii')

        regs = gdb.execute("info registers %s" % args[0], to_string=True)
        if regs:
            regs = regs.splitlines()
            result = to_int(regs[0].split()[1])
            registers[args[0]] = result


class ReadMemory(gdb.Command):
    def __init__(self):
        super(ReadMemory, self).__init__("readmemory", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = arg.split()
        str = args[0]
        if str.startswith('0x'):
            address = int(args[0], 16)
        else:
            address = int(args[0])
        memory_view = gdb.selected_inferior().read_memory(address, 8)
        mem_val = int(to_hexstr(memory_view), 16)
        print(mem_val)


class Triton(gdb.Command):
    def __init__(self):
        super(Triton, self).__init__("triton", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = arg.split()
        print(symbolic.getvmmap())


class Symbolic(gdb.Command):
    def __init__(self):
        super(Symbolic, self).__init__("symbolic", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = arg.split()
        str = args[0]
        if str.startswith('0x'):
            address = int(args[0], 16)
        else:
            address = int(args[0])
        str = args[1]
        if str.startswith('0x'):
            length = int(args[1], 16)
        else:
            length = int(args[1])
        setArchitecture(ARCH.X86)
        #enableSymbolicEngine(True)

        # Define symbolic optimizations
        enableMode(MODE.ALIGNED_MEMORY, True)
        enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Load the binary
        loadBinary(symbolic.getfile())
        vmmap = symbolic.getvmmap()
        print(vmmap)
        """
        for stack in vmmap[0:3]:
            print(hex(stack[0]), hex(stack[1]))
            loadStack(stack[0], stack[1])
        """

        stack = vmmap[-1]
        print(hex(stack[0]), hex(stack[1]))
        loadStack(stack[0], stack[1])

        symbolic.getregs()
        symbolic.setregs()

        #addCallback(needConcreteMemoryValue, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        #addCallback(needConcreteRegisterValue, CALLBACK.GET_CONCRETE_REGISTER_VALUE)

        for index in range(length):
            convertMemoryToSymbolicVariable(
                MemoryAccess(address + index, CPUSIZE.BYTE))

        # Emulate from the verification function
        print(symbolic.getfile())
        raw_input("Press any key to start emulate")
        emulate(0x8048490)
        return


symbolic = SYMBOLIC()
ReadRegister()
ReadMemory()
Triton()
Symbolic()


# Emulate the CheckSolution() function.
def emulate(pc):
    print('[+] Starting emulation.')
    while pc:
        # Fetch opcodes
        opcodes = getConcreteMemoryAreaValue(pc, 16)

        # Create the Triton instruction
        instruction = Instruction()
        instruction.setOpcodes(opcodes)
        instruction.setAddress(pc)

        # Process
        processing(instruction)
        print(instruction)
        # 40078B: cmp eax, 1
        # eax must be equal to 1 at each round.
        if instruction.getAddress() == 0x080484B5:
            tstart = time.time()
            # Slice expressions
            eax = getSymbolicExpressionFromId(getSymbolicRegisterId(REG.EAX))
            eax = ast.extract(31, 0, eax.getAst())

            # Define constraint
            cstr = ast.assert_(
                ast.land(getPathConstraintsAst(),
                         ast.equal(eax, ast.bv(0x0AD6D, 32))))

            print('[+] Asking for a model, please wait...')
            model = getModel(cstr)
            for k, v in model.items():
                value = v.getValue()
                getSymbolicVariableFromId(k).setConcreteValue(value)
                print('[+] Symbolic variable %02d = %02x (%c)' %
                      (k, value, chr(value)))
            tend = time.time()
            print("It cost %f sec" % (tend - tstart))

        if instruction.getAddress() == 0x080484BC:
            tstart = time.time()
            eip = getSymbolicExpressionFromId(getSymbolicRegisterId(REG.EIP))
            expr = getFullAst(eip.getAst())
            #print(expr)

            eip = ast.extract(31, 0, eip.getAst())

            # Define constraint
            cstr = ast.assert_(
                ast.land(getPathConstraintsAst(),
                         ast.equal(eip, ast.bv(0x080484BE, 32))))

            print('[+] Asking for a model, please wait...')
            model = getModel(cstr)
            for k, v in model.items():
                value = v.getValue()
                getSymbolicVariableFromId(k).setConcreteValue(value)
                print('[+] Symbolic variable %02d = %02x (%c)' %
                      (k, value, chr(value)))
            tend = time.time()
            print("It cost %f sec" % (tend - tstart))

        # Next
        pc = getConcreteRegisterValue(REG.EIP)

    print('[+] Emulation done.')
    return


def loadStack(start, end):
    size = end - start
    memory_view = gdb.selected_inferior().read_memory(start, size)
    lis = map(ord, list(memory_view))
    setConcreteMemoryAreaValue(start, lis)


# Load segments into triton.
def loadBinary(path):
    binary = Elf(path)
    raw = binary.getRaw()

    phdrs = binary.getProgramHeaders()
    for phdr in phdrs:
        offset = phdr.getOffset()
        size = phdr.getFilesz()
        vaddr = phdr.getVaddr()
        print('[+] Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size))
        setConcreteMemoryAreaValue(vaddr, raw[offset:offset + size])

    phdrs = binary.getSectionHeaders()
    for phdr in phdrs:
        offset = phdr.getOffset()
        size = phdr.getSize()
        vaddr = phdr.getAddr()
        print('[+] Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size))
        setConcreteMemoryAreaValue(vaddr, raw[offset:offset + size])
    return


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

    memory_view = gdb.selected_inferior().read_memory(mem_addr, mem_size)
    mem_val = int(to_hexstr(memory_view), 16)
    print("Memory from %s length %d: %s" %
          (str(hex(mem_addr)), mem_size, to_hexstr(memory_view)))
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
        reg_val = symbolic.getreg('eflags')
        reg_val = getConcreteRegisterValue(Register(getattr(REG, reg.upper())))
        print("Eflags:" + str(reg_val))
        return
    else:
        reg_val = symbolic.getreg(reg)

    print("Got %s value: %s" % (reg, str(hex(reg_val))))
    #setConcreteRegisterValue(Register(getattr(REG, reg.upper()),reg_val))
