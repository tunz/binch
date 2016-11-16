from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import sys, os
from . import signals

class Disassembler():

    memory = []

    def __init__(self, filename):
        self.filename = filename
        self.loadELF(filename)
        self.init_disasmblr()
        self.init_asmblr()

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

    def load_code_segments(self, segments, filename):
        memory = []
        for elf_segment in segments:
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
                memory.append((vaddr, offset, memsz, data))
        return memory

    def load_symbol_table(self, symbols):
        syms = dict()
        thumbs = list()
        for symbol in symbols:
            if symbol['st_info']['type'] == 'STT_FUNC':
                if self.is_thumb_addr(symbol['st_value']):
                    syms[symbol['st_value'] - 1] = symbol.name
                else:
                    syms[symbol['st_value']] = symbol.name
            elif self.arch == 'ARM' and symbol['st_info']['type'] == 'STT_NOTYPE':
                if symbol.name == '$t':  # Thumb
                    thumbs.append((symbol['st_value'], True))
                elif symbol.name == '$a':   #ARM
                    thumbs.append((symbol['st_value'], False))
        return syms, thumbs

    def load_section_info(self, sections):
        symtab = dict()
        thumbtab = list()
        code_addrs = []

        for section in sections:
            if isinstance(section, SymbolTableSection):
                syms, thumbs = self.load_symbol_table(section.iter_symbols())
                symtab.update(syms)
                thumbtab.extend(thumbs)
            elif section['sh_flags'] == 6: # Assumption: Code section's flag is AX (ALLOC=2 & EXEC=4)
                code_addrs.append({'address': section['sh_addr'], 'size': section['sh_size']})
        return symtab, thumbtab, code_addrs

    def loadELF(self, filename):
        try:
            elf = ELFFile(open(filename, 'rb'))
        except:
            raise Exception("[-] This file is not an ELF file: %s" % filename)

        self.arch = elf.get_machine_arch()
        self.entry = elf.header.e_entry
        self.memory = self.load_code_segments(elf.iter_segments(), filename)
        self.symtab, self.thumbtab, self.code_addrs = self.load_section_info(elf.iter_sections())

        self.thumbtab.sort(key=lambda tup: tup[0])
        self.code_addrs = sorted(self.code_addrs, key=lambda k: k['address'])

    def init_asmblr(self):
        arch = {'x86':KS_ARCH_X86,'x64':KS_ARCH_X86, 'ARM':KS_ARCH_ARM}[self.arch]
        mode = {'x86':KS_MODE_32, 'x64':KS_MODE_64, 'ARM':KS_MODE_ARM}[self.arch]
        self.ks = Ks(arch, mode)
        if self.arch == 'ARM':
            self.t_ks = Ks(arch, CS_MODE_THUMB)

    def init_disasmblr(self):
        arch = {'x86':CS_ARCH_X86,'x64':CS_ARCH_X86, 'ARM':CS_ARCH_ARM}[self.arch]
        mode = {'x86':CS_MODE_32, 'x64':CS_MODE_64, 'ARM':CS_MODE_ARM}[self.arch]
        self.md = Cs(arch, mode)
        self.md.detail = True
        if self.arch == 'ARM':
            self.t_md = Cs(arch, CS_MODE_THUMB)
            self.t_md.detail = True

    def disasm(self, address, size=None):
        if self.arch == 'ARM' and self.thumbtab:
            disasms = []
            thumb = bool(address & 1)
            address = address & 0xfffffffe
            for addr, isthumb in self.thumbtab:
                if address < addr:
                    md = self.md if not thumb else self.t_md
                    disasms.extend([i for i in md.disasm(self.read_memory(address, addr-address), address)])
                address = addr
                thumb = isthumb
            return disasms
        else:
            return [i for i in self.md.disasm(self.read_memory(address, size), address)]

    def asm(self, asmcode, thumb=False):
        ks = self.ks if not thumb else self.t_ks
        try:
            encoding, count = ks.asm(asmcode)
        except KsError as err:
            msg = "Error: %s" % err
            signals.set_message.send(0, message=msg, expire=2)
            return ""
        return ''.join(map(chr, encoding))

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
                        os.chmod(filename, 0o755)
                        return "Successfully save to '%s'" % filename
                    except Exception as e:
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
        return self.arch == 'ARM' and (address & 1) == 1
