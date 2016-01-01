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

    def read_memory(self, address, size):
        for vaddr, foffset, memsize, mem in self.memory:
            if address >= vaddr and address <= vaddr + memsize:
                if size:
                    return mem[address - vaddr : address - vaddr + size]
                else:
                    return mem[address - vaddr:]
        return ""

    def write_memory(self, address, data):
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
            self.elf = ELFFile(file(filename))
        except:
            raise Exception("[-] This file is not an ELF file: %s" % filename)

        self.arch = self.elf.get_machine_arch()

        if self.arch == 'ARM':
            self.arm_arch = self.get_tag_cpu_arch()

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

            with open(filename, 'rb') as f:
                f.seek(offset, 0)
                data = f.read(filesz)
                self.memory.append((vaddr, offset, memsz, data))

        self.entry = self.elf.header.e_entry

        self.symtab = dict()
        self.thumbtab = list()

        self.code_addrs = []

        for section in self.elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                # Load symbol table
                for symbol in section.iter_symbols():
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        if self.is_thumb_addr(symbol['st_value']):
                            self.symtab[symbol['st_value'] - 1] = symbol.name
                        else:
                            self.symtab[symbol['st_value']] = symbol.name
                    elif self.arch == 'ARM' and symbol['st_info']['type'] == 'STT_NOTYPE':
                        if symbol.name == '$t':  # Thumb
                            self.thumbtab.append((symbol['st_value'], True))
                        elif symbol.name == '$a':   #ARM
                            self.thumbtab.append((symbol['st_value'], False))
            else:
                # Assumption: Code section's flag is AX (ALLOC=2, EXEC=4)
                if section['sh_flags'] == 6:
                    self.code_addrs.append({'address': section['sh_addr'], 'size': section['sh_size']})

        self.thumbtab.sort(key=lambda tup: tup[0])

        self.code_addrs = sorted(self.code_addrs, key=lambda k: k['address'])

        arch = {'x86':CS_ARCH_X86,'x64':CS_ARCH_X86, 'ARM':CS_ARCH_ARM}[self.arch]
        mode = {'x86':CS_MODE_32, 'x64':CS_MODE_64, 'ARM':CS_MODE_ARM}[self.arch]
        self.md = Cs(arch, mode)
        self.md.detail = True
        if self.arch == 'ARM':
            self.t_md = Cs(arch, CS_MODE_THUMB)
            self.t_md.detail = True

    def disasm(self, address, size=None):
        if self.arch == 'ARM':
            disasms = []
            thumb = False
            if (address & 1) == 1:
                thumb = True
            address = address & -2
            for addr, isthumb in self.thumbtab:
                if address < addr:
                    if thumb:
                        disasms.extend([i for i in self.t_md.disasm(self.read_memory(address, addr-address), address)])
                    else:
                        disasms.extend([i for i in self.md.disasm(self.read_memory(address, addr-address), address)])
                address = addr
                thumb = isthumb
            return disasms
        else:
            return [i for i in self.md.disasm(self.read_memory(address, size), address)]

    def is_thumb_instr(self, instr):
        return instr._cs.mode == CS_MODE_THUMB

    def save(self):
        def save_binary(filename):
            def save_binary_yes(yn, filename):
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

            if filename == "":
                filename = self.filename

            if os.path.exists(filename):
                return (filename+" already exists, Overwrite?", save_binary_yes, filename)
            else:
                return save_binary_yes('y', filename)

        signals.set_prompt.send(self, text="Save to (filename): ", callback=save_binary)

    def is_thumb_addr(self, address):
        if self.arch == 'ARM' and (address & 1) == 1:
            return True
        else:
            return False

    # Find the architecture of an ARM EFL binary
    def get_tag_cpu_arch(self):
        from struct import unpack
        tag_list = [
                'Pre_v4',
                'v4',       # e.g. SA110
                'v4T',      # e.g. ARM7TDMI
                'v5T',      # e.g. ARM9TDMI
                'v5TE',     # e.g. ARM946E_S
                'v5TEJ',    # e.g. ARM926EJ_S
                'v6',       # e.g. ARM1136J_S
                'v6KZ',     # e.g. ARM1176JZ_S
                'v6T2',     # e.g. ARM1156T2_S
                'v6K',      # e.g. ARM1176JZ_S
                'v7',       # e.g. Cortex A8, Cortex M3
                'v6_M',     # e.g. Cortex M1
                'v6S_M',    # v6_M with the System extensions
                'v7E_M',    # v7_M with DSP extensions
                'v8'        # v8,v8.1a AArch32
                ]

        attr = self.elf.get_section_by_name('.ARM.attributes')
        attr_data = attr.data()

        if attr_data[0] != 'A':
            return ""

        idx = 1
        size = unpack('<L', attr_data[idx:idx+4])[0]
        idx += 4

        if attr_data[idx:idx+5] != "aeabi":
            return ""
        idx += 6

        while idx - 1 < size:
            tag_number = attr_data[idx]
            idx += 1
            if tag_number in "\x04\x05\x67\x32":
                idx = attr_data.find("\x00",idx) + 1
            else:
                result = 0
                shift = 0
                while True:
                    byte = unpack('B', attr_data[idx])[0]
                    idx += 1
                    result |= ((byte & 0x7F) << shift)
                    if (byte & 0x80) == 0:
                        break
                    shift += 7
                if tag_number == "\x06": # tag_arch
                    return tag_list[result]

        return ""
