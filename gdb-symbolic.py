from triton import *
import os
import sys
sys.path.append(os.getcwd())
from utils import *

class ReadMemory(gdb.Command):
    def __init__(self):
        super(ReadMemory, self).__init__("readmemory", gdb.COMMAND_DATA)
    def invoke(self,arg, from_tty):
        args = arg.split()
        str = args[0]
        """
        try:
            str = str.encode('ascii', 'ignore')
        except:
            pass
        str = decode_string_escape(str)
        """
        if str.startswith('0x'):
            address = int(args[0],16)
        else:
            address = int(args[0])
        memory_view = gdb.selected_inferior().read_memory(address, 8)
        print(to_hexstr(memory_view))

class Triton(gdb.Command):
    def __init__(self):
        super(Triton, self).__init__("triton", gdb.COMMAND_DATA)
    def invoke(self,arg, from_tty):
        args = arg.split()
        print(args[0])
        print(args[1])

class Symbolic(gdb.Command):
    def __init__(self):
        super(Symbolic, self).__init__("symbolic", gdb.COMMAND_DATA)
    def invoke(self,arg, from_tty):
        setArchitecture(ARCH.X86)

        # Define symbolic optimizations
        enableMode(MODE.ALIGNED_MEMORY, True)
        enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

        # Load the binary
        loadBinary('./examples/crackme_hash')


        """
        setConcreteRegisterValue(Register(REG.EAX, 0xf7fb3dbc))
        setConcreteRegisterValue(Register(REG.ECX, 0xffffcd20))
        setConcreteRegisterValue(Register(REG.EDX, 0xffffcd44))
        setConcreteRegisterValue(Register(REG.ESP, 0xffffcd04))
        setConcreteRegisterValue(Register(REG.EBP, 0xffffcd08))
        setConcreteMemoryValue(MemoryAccess(0xffffcd20,4,2))
        """
        #print(getConcreteMemoryValue(0xf7fb3dbc))
        #print(hex(getConcreteRegisterValue(REG.EAX)))
        addCallback(needConcreteMemoryValue, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
        addCallback(needConcreteRegisterValue, CALLBACK.GET_CONCRETE_REGISTER_VALUE)

        for index in range(5):
            convertMemoryToSymbolicVariable(MemoryAccess(0xffffcf7b+index, CPUSIZE.BYTE))

        # Emulate from the verification function
        emulate(0x8048482)

        sys.exit(0)

ReadMemory()
Triton()

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
        if instruction.getAddress() == 0x08048543:
            # Slice expressions
            eax   = getSymbolicExpressionFromId(getSymbolicRegisterId(REG.EAX))
            eax   = ast.extract(31, 0, eax.getAst())

            # Define constraint
            cstr  = ast.assert_(
                        ast.land(
                            getPathConstraintsAst(),
                            ast.equal(eax, ast.bv(0x0AD6D, 32))
                        )
                    )

            print('[+] Asking for a model, please wait...')
            model = getModel(cstr)
            for k, v in model.items():
                value = v.getValue()
                getSymbolicVariableFromId(k).setConcreteValue(value)
                print('[+] Symbolic variable %02d = %02x (%c)' %(k, value, chr(value)))

        # Next
        pc = getConcreteRegisterValue(REG.EIP)

    print('[+] Emulation done.')
    return

# Load segments into triton.
def loadBinary(path):
    binary = Elf(path)
    raw    = binary.getRaw()
    phdrs  = binary.getProgramHeaders()
    for phdr in phdrs:
        offset = phdr.getOffset()
        size   = phdr.getFilesz()
        vaddr  = phdr.getVaddr()
        print('[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size))
        setConcreteMemoryAreaValue(vaddr, raw[offset:offset+size])
    return

def needConcreteMemoryValue(mem):
#    print(mem)
    print(hex(mem.getAddress()))
    print(mem.getSize())

def needConcreteRegisterValue(reg):
    print(reg.getName())


"""
if __name__ == '__main__':
    # Define the target architecture
    setArchitecture(ARCH.X86)

    # Define symbolic optimizations
    enableMode(MODE.ALIGNED_MEMORY, True)
    enableMode(MODE.ONLY_ON_SYMBOLIZED, True)

    # Load the binary
    loadBinary('./examples/crackme_hash')


    setConcreteRegisterValue(Register(REG.EAX, 0xf7fb3dbc))
    setConcreteRegisterValue(Register(REG.ECX, 0xffffcd20))
    setConcreteRegisterValue(Register(REG.EDX, 0xffffcd44))
    setConcreteRegisterValue(Register(REG.ESP, 0xffffcd04))
    setConcreteRegisterValue(Register(REG.EBP, 0xffffcd08))
    setConcreteMemoryValue(MemoryAccess(0xffffcd20,4,2))
    #print(getConcreteMemoryValue(0xf7fb3dbc))
    #print(hex(getConcreteRegisterValue(REG.EAX)))
    addCallback(needConcreteMemoryValue, CALLBACK.GET_CONCRETE_MEMORY_VALUE)
    addCallback(needConcreteRegisterValue, CALLBACK.GET_CONCRETE_REGISTER_VALUE)

    for index in range(5):
        convertMemoryToSymbolicVariable(MemoryAccess(0xffffcf7b+index, CPUSIZE.BYTE))

    # Emulate from the verification function
    emulate(0x8048482)

    sys.exit(0)

"""
