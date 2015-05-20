from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import sys

class Disassembler():

    memory = []

    def __init__(self, filename):
        self.loadELF(filename)

    def readMemory(self, address, size):
        for start, end, data in self.memory:
            if address >= start and address <= end:
                return data[address - start:size]
        return ""

    def loadELF(self, filename):
        try:
            self.elf = ELFFile(file(sys.argv[1]))
        except:
            print "[-] It is not ELF file: "+sys.argv[1]
            sys.exit()

        # Load code segments
        for elf_segment in self.elf.iter_segments():
            if elf_segment.header.p_type != 'PT_LOAD':
                continue

            align = 0x1000
            ELF_PAGEOFFSET = elf_segment.header.p_vaddr & (align-1)

            memsz = elf_segment.header.p_memsz + ELF_PAGEOFFSET
            offset = elf_segment.header.p_offset - ELF_PAGEOFFSET
            filesz = elf_segment.header.p_filesz + ELF_PAGEOFFSET
            vaddr = elf_segment.header.p_vaddr - ELF_PAGEOFFSET
            memsz = (memsz + align ) & ~(align-1)

            with open(sys.argv[1], 'rb') as f:
                f.seek(offset, 0)
                data = f.read(filesz)
                self.memory.append((vaddr, vaddr+memsz, data))

        self.entry = self.elf.header.e_entry

        # Load symbol table
        self.symtab = dict()
        for section in self.elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        self.symtab[symbol['st_value']] = symbol.name

        arch = {'x86':CS_ARCH_X86,'x64': CS_ARCH_X86}[self.elf.get_machine_arch()]
        mode = {'x86': CS_MODE_32, 'x64': CS_MODE_64}[self.elf.get_machine_arch()]
        self.md = Cs(arch, mode)

    def disasm(self, address, size=None):
        count = 0
        result=[]
        for i in self.md.disasm(self.readMemory(address, size), address):
            line = "0x%x\t%s\t%s\t%s" %(i.address,
                    ' '.join(["%02x" % (j) for j in i.bytes]),
                    i.mnemonic, i.op_str)
            result.append(line)

        return result
