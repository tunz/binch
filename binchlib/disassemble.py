from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import sys, os
import signals

class Disassembler():

    memory = []

    def __init__(self, filename):
        self.filename = filename
        self.loadELF(filename)

    def readMemory(self, address, size):
        for vaddr, foffset, memsize, mem in self.memory:
            if address >= vaddr and address <= vaddr + memsize:
                if size:
                    return mem[address - vaddr : address - vaddr + size]
                else:
                    return mem[address - vaddr:]
        return ""

    def writeMemory(self, address, data):
        offset = self.addr2offset(address)
        for idx, (vaddr, foffset, memsize, mem) in enumerate(self.memory):
            if offset >= foffset and offset <= foffset + memsize:
                mem=list(mem)
                for i in range(0, len(data)):
                    if offset - foffset + i < len(mem):
                        mem[offset - foffset + i] = data[i]
                    else:
                        mem.append(data[i])
                        memsize+=1
                self.memory[idx] = (vaddr, foffset, memsize, ''.join(mem))

    def addr2offset(self, address):
        for vaddr, foffset, memsize, mem in self.memory:
            if address >= vaddr and address <= vaddr + memsize:
                return address - vaddr + foffset
        return -1

    def loadELF(self, filename):
        try:
            self.elf = ELFFile(file(sys.argv[1]))
        except:
            print "[-] It is not ELF file: "+sys.argv[1]
            sys.exit()

        self.arch = self.elf.get_machine_arch()

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
                self.memory.append((vaddr, offset, memsz, data))

        self.entry = self.elf.header.e_entry

        # Load symbol table
        self.symtab = dict()
        self.thumbtab = list()
        for section in self.elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        if self.isThumb(symbol['st_value']):
                            self.symtab[symbol['st_value'] - 1] = symbol.name
                        else:
                            self.symtab[symbol['st_value']] = symbol.name
                    elif self.arch == 'ARM' and symbol['st_info']['type'] == 'STT_NOTYPE':
                        if symbol.name == '$t':  # Thumb
                            self.thumbtab.append((symbol['st_value'], True))
                        elif symbol.name == '$a':   #ARM
                            self.thumbtab.append((symbol['st_value'], False))

        self.thumbtab.sort(key=lambda tup: tup[0])

        text_section = self.elf.get_section_by_name(b'.text')
        self.text = text_section.data()
        self.text_addr = text_section['sh_addr']
        self.text_size = text_section['sh_size']

        arch = {'x86':CS_ARCH_X86,'x64':CS_ARCH_X86, 'ARM':CS_ARCH_ARM}[self.arch]
        mode = {'x86':CS_MODE_32, 'x64':CS_MODE_64, 'ARM':CS_MODE_ARM}[self.arch]
        self.md = Cs(arch, mode)
        if self.arch == 'ARM':
            self.t_md = Cs(arch, CS_MODE_THUMB)

    def disasm(self, address, size=None):
        if self.arch == 'ARM':
            disasms = []
            thumb = False
            if (address & 1) == 1:
                thumb = True
            address = address & -2
            for addr, isThumb in self.thumbtab:
                if address < addr:
                    if thumb:
                        disasms.extend([i for i in self.t_md.disasm(self.readMemory(address, addr-address), address)])
                    else:
                        disasms.extend([i for i in self.md.disasm(self.readMemory(address, addr-address), address)])
                address = addr
                thumb = isThumb
            return disasms
        else:
            return [i for i in self.md.disasm(self.readMemory(address, size), address)]

    def save(self):
        def saveBinary(filename):
            def saveBinaryYes(yn, filename):
                if yn == 'y':
                    try:
                        original_binary = open(self.filename, 'rb').read()
                        f = open(filename, 'wb')
                        f.write(original_binary)
                        for vaddr, foffset, memsize, mem in self.memory:
                            f.seek(foffset, 0)
                            f.write(mem)
                        f.close()
                        os.chmod(filename, 0755)
                        return "Successfully save to '%s'" % filename
                    except Exception, e:
                        return "Fail to save binary: "+str(e)

                return "Fail to save binary"

            if os.path.exists(filename):
                return (filename+" already exists, Overwrite?", saveBinaryYes, filename)
            else:
                return saveBinaryYes('y', filename)

        signals.set_prompt.send(self, text="Save to (filename): ", callback=saveBinary)

    def isThumb(self, address):
        if self.arch == 'ARM' and (address & 1) == 1:
            return True
        else:
            return False
