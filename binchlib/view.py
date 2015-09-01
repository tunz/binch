import urwid
from disassemble import *
from assembler import *
from statusbar import *
from capstone.x86 import X86_OP_IMM
from capstone.arm import ARM_OP_IMM
import signals
import traceback

class DisassembleText(urwid.Text):

    def selectable(self):
        return False

    def keypress(self, size, key):
        return key

class DisassembleInstruction(urwid.WidgetWrap):
    def __init__(self, instrSet, disasmblr, view):
        urwid.WidgetWrap.__init__(self, None)
        instr = instrSet[0]
        self.instruction = instr
        self.isthumb = instrSet[1]
        self.edit_mode = False
        self.hex_edit_mode = False
        self.disasmblr = disasmblr
        self.view = view
        self.mode_plain()

    def selectable(self):
        return True

    def mode_plain(self):
        self._w = urwid.Columns([('fixed', 102, urwid.Text("%s%s%s%s" % (
                                hex(self.instruction.address).rstrip('L').ljust(12, ' '),
                                ' '.join(["%02x" % j for j in self.instruction.bytes]).ljust(27, ' ')+' ',
                                self.instruction.mnemonic.ljust(8, ' '),
                                self.instruction.op_str))
                                )])
        self._w = urwid.AttrMap(self._w, 'bg', 'reveal focus')

    def mode_edit1(self):
        self.address = urwid.Text(hex(self.instruction.address).rstrip('L'))
        self.opcode = urwid.Text(' '.join(["%02x" % j for j in self.instruction.bytes]))
        self._w = urwid.Columns([
            ('fixed', 12, self.address),
            ('fixed', 28, self.opcode),
            ('fixed', 62, self._editbox)
            ])
        self._w = urwid.AttrMap(self._w, 'bg', 'reveal focus')

    def mode_edit2(self):
        self.address = urwid.Text(hex(self.instruction.address).rstrip('L'))
        self.instr = urwid.Text("%s%s" % (self.instruction.mnemonic.ljust(8, ' '), self.instruction.op_str))
        self._w = urwid.Columns([
            ('fixed', 12, self.address),
            ('fixed', 28, self._hexeditbox),
            ('fixed', 62, self.instr)
            ])
        self._w = urwid.AttrMap(self._w, 'bg', 'reveal focus')

    def modify_opcode(self, opcode, original_opcode=None):
        if opcode == "":
            self.mode_plain()
            return

        if original_opcode == None:
            original_opcode = ''.join(map(chr, self.instruction.bytes))

        original_opcode_len = len(original_opcode)

        if len(opcode) < original_opcode_len:
            if self.disasmblr.arch == 'ARM':
                opcode = opcode.ljust(original_opcode_len, "\x00") # Fill with nop
            else:
                opcode = opcode.ljust(original_opcode_len, "\x90") # Fill with nop
        elif len(opcode) > original_opcode_len:
            safe_opcode_len = 0
            opcode_data = self.disasmblr.read_memory(self.instruction.address, 0x20)
            if self.isthumb:
                disasm_code = self.disasmblr.t_md.disasm(opcode_data, 0x20)
            else:
                disasm_code = self.disasmblr.md.disasm(opcode_data, 0x20)
            for i in disasm_code:
                if len(opcode) > safe_opcode_len:
                    safe_opcode_len += len(i.bytes)
            if self.disasmblr.arch == 'ARM':
                opcode = opcode.ljust(safe_opcode_len, "\x00") # Fill with nop
            else:
                opcode = opcode.ljust(safe_opcode_len, "\x90") # Fill with nop

        self.disasmblr.write_memory(self.instruction.address, opcode)

        if original_opcode_len == len(opcode):
            if self.isthumb:
                code = [i for i in self.disasmblr.t_md.disasm(opcode, self.instruction.address)][0]
            else:
                code = [i for i in self.disasmblr.md.disasm(opcode, self.instruction.address)][0]

            if (len(code.operands) == 1 and
                ((self.disasmblr.arch in ['x86','x64'] and code.operands[0].type == X86_OP_IMM) or
                        (self.disasmblr.arch == 'ARM' and code.operands[0].type == ARM_OP_IMM))):
                self.view.update_list(self.view.disasmlist._w.focus_position)

            self.instruction = code
            self.mode_plain()
        else:
            def update_all(yn, arg):
                if yn == "y":
                    self.view.update_list(self.view.disasmlist._w.focus_position)
                else:
                    self.modify_opcode(original_opcode)

            signals.set_prompt_yn.send(self,
                    text="This operation will break following codes, is it okey?",
                    callback=update_all,
                    arg=None
                    )

    def keypress(self, size, key):
        if self.edit_mode:
            if key == "esc":
                self.edit_mode = False
                self.mode_plain()
            elif key == "enter":
                self.edit_mode = False
                asmcode = self._editbox.get_edit_text()
                if self.disasmblr.arch == 'ARM':
                    if self.isthumb:
                        opcode = assemble(asmcode, 'thumb', self.disasmblr.arm_arch)
                    else:
                        opcode = assemble(asmcode, self.disasmblr.arch, self.disasmblr.arm_arch)
                else:
                    opcode = assemble(asmcode, self.disasmblr.arch)
                self.modify_opcode(opcode)
            elif isinstance(key, basestring):
                self._w.keypress(size, key)
            else:
                return key
        elif self.hex_edit_mode:
            if key == "esc":
                self.hex_edit_mode = False
                self.mode_plain()
            elif key == "enter":
                self.hex_edit_mode = False
                hexcode = self._hexeditbox.get_edit_text()
                original_hexcode = ''.join(map(chr, self.instruction.bytes))
                try:
                    opcode = hexcode.replace(' ','').decode('hex')
                    self.modify_opcode(opcode, original_hexcode)
                except Exception, e:
                    msg = "Error: "+str(e)
                    self.modify_opcode(original_hexcode, original_hexcode)
                    signals.set_message.send(0, message=msg, expire=2)
                    self.mode_plain()

            elif isinstance(key, basestring):
                self._w.keypress(size, key)
            else:
                return key
        else:
            if key == "enter":
                self._editbox = urwid.Edit("", "%s%s" % (self.instruction.mnemonic.ljust(8, ' '),
                                                                            self.instruction.op_str))
                self.mode_edit1()
                self.edit_mode = True
            elif key == "h":
                self._hexeditbox = urwid.Edit("", ' '.join(["%02x" % j for j in self.instruction.bytes]))
                self.mode_edit2()
                self.hex_edit_mode = True
            elif key == "f":
                followAddress = False
                mnemonic = self.instruction.mnemonic
                if self.disasmblr.arch in ['x86', 'x64'] and (mnemonic[0] == 'j' or mnemonic == 'call'):
                    if self.instruction.operands[0].type == X86_OP_IMM:
                        followAddress = True
                elif self.disasmblr.arch == 'ARM' and mnemonic[0] == 'b':
                    if self.instruction.operands[0].type == ARM_OP_IMM:
                        followAddress = True
                if followAddress:
                    address = int(self.instruction.op_str.lstrip('#'), 16)
                    try:
                        self.view.disasmlist.set_focus(self.view.index_map[address])
                        self.view.history.append(hex(self.instruction.address).rstrip('L'))
                        msg = "Jump to "+hex(address)
                        signals.set_message.send(0, message=msg, expire=1)
                    except:
                        msg = "Error: Fail to jump... please report it"
                        signals.set_message.send(0, message=msg, expire=2)
            elif key == "d" or key == "D":
                def fill_with_nop(yn, arg):
                    if yn == 'y':
                        if self.disasmblr.arch == 'ARM':
                            self.modify_opcode("\x00")
                        else:
                            self.modify_opcode("\x90")
                signals.set_prompt_yn.send(self, text="Remove this line?", callback=fill_with_nop, arg=None)
            else:
                if key == "j" or key == "J":
                    key = "down"
                elif key == "k" or key == "K":
                    key = "up"
                return key

class SymbolText(urwid.Text):

    def selectable(self):
        return False

    def keypress(self, size, key):
        return key

class DisassembleList(urwid.WidgetWrap):
    def __init__(self, dList):
        urwid.WidgetWrap.__init__(self, None)
        self.update_list(dList)

    def set_focus(self, idx):
        self._w.set_focus(idx)

    def update_list(self, dList, focus=0):
        self._w = urwid.ListBox(urwid.SimpleListWalker(dList))
        if focus:
            self._w.set_focus(focus)

    def selectable(self):
        return True

    def keypress(self, size, key):
        key = super(self.__class__, self).keypress(size, key)
        if key == "j":
            key = "down"
        elif key == "k":
            key = "up"
        return key

class DisassembleWindow(urwid.Frame):
    def __init__(self, view, body, header, footer):
        urwid.Frame.__init__(
                self, body,
                header if header else None,
                footer if footer else None
            )
        self.view = view
        signals.focus.connect(self.sig_focus)

    def sig_focus(self, sender, section):
        self.focus_position = section

    def keypress(self, size, key):
        key = super(self.__class__, self).keypress(size, key)
        return key

class DisassembleView:
    palette = [('header', 'white', 'black'),
            ('reveal focus', 'black', 'light gray', 'standout'),
            ('status', 'white', 'dark blue', 'standout')]

    def __init__(self, filename):
        self.header = urwid.Text(" BINCH: %s" % (filename))

        self.disasmblr = Disassembler(filename)

        items = self.setup_list()
        self.disasmlist = DisassembleList(items)
        start_index = self.find_index(self.disasmblr.entry)
        if start_index != -1:
            self.disasmlist.set_focus(start_index)

        self.history = list()

        self.body = urwid.Padding(self.disasmlist, 'center', 105)
        self.body = urwid.Filler(self.body, ('fixed top',1), ('fixed bottom',1))

        self.footer = StatusBar("HotKeys -> g: Go to a address | s: Save | d: Remove | enter: Modify | q: Quit", self)
        self.view = DisassembleWindow(self,
                urwid.AttrWrap(self.body, 'body'),
                urwid.AttrWrap(self.header, 'head'),
                self.footer)

        signals.call_delay.connect(self.sig_call_delay)

    def find_index(self, address):
        try:
            if self.disasmblr.isthumb(address):
                return self.index_map[address & -2]
            else:
                return self.index_map[address]
        except KeyError:
            return -1

    def setup_list(self):
        body = self.disasmblr.disasm(self.disasmblr.text_addr)
        items = []
        idx = 0
        self.index_map = dict()
        for i, isthumb in body:
            address = i.address
            symbol = None
            try: symbol = self.disasmblr.symtab[address]
            except:
                if isthumb:
                    try: symbol = self.disasmblr.symtab[address - 1]
                    except: pass

            if symbol:
                items.append(SymbolText(" "))
                items.append(SymbolText(" < %s >" % symbol))
                idx+=2
            items.append(DisassembleInstruction((i, isthumb), self.disasmblr, self))
            self.index_map[address] = idx
            idx+=1

        return items

    def update_list(self, focus=0):
        items = self.setup_list()
        self.disasmlist.update_list(items, focus)

    def update_status(self, *arg):
        signals.redraw_status.send(self)
        self.loop.set_alarm_in(0.03, self.update_status)

    def main(self):
        self.loop = urwid.MainLoop(self.view, self.palette,
                handle_mouse=False,
                unhandled_input=self.unhandled_input)

        self.loop.set_alarm_in(0.03, self.update_status)

        try:
            self.loop.run()
        except:
            self.loop.stop()
            print traceback.format_exc()

    def unhandled_input(self, k):
        def goto(text):
            try:
                address = int(text, 16)
            except:
                return "It is not hexadecimal number: "+text

            if address in self.index_map:
                self.history.append(self.disasmlist._w.body[self.disasmlist._w.focus_position].address.text)
                self.disasmlist.set_focus(self.index_map[address])
                return "Jump to "+hex(address)
            else:
                for i in range(1, 0x10):
                    if address - i in self.index_map:
                        self.history.append(self.disasmlist._w.body[self.disasmlist._w.focus_position].address.text)
                        self.disasmlist.set_focus(self.index_map[address - i])
                        return "Jump to "+hex(address - i)
                    elif address + i in self.index_map:
                        self.history.append(self.disasmlist._w.body[self.disasmlist._w.focus_position].address.text)
                        self.disasmlist.set_focus(self.index_map[address + i])
                        return "Jump to "+hex(address + i)

                return "Invalid address: "+hex(address)

        if k in ('q', 'Q'):
            def ask_quit(yn, arg):
                if yn == 'y':
                    raise urwid.ExitMainLoop()
            signals.set_prompt_yn.send(self, text="Quit?", callback=ask_quit, arg=None)
        elif k in ('g', 'G'):
            signals.set_prompt.send(self, text="Goto: ", callback=goto)
        elif k in ('s', 'S'):
            self.disasmblr.save()
        elif k == "esc":
            if len(self.history) > 0:
                address = int(self.history[-1],16)
                del self.history[-1]
                self.disasmlist.set_focus(self.index_map[address])

    def sig_call_delay(self, sender, seconds, callback):
        def cb(*_):
            return callback()
        self.loop.set_alarm_in(seconds, cb)
