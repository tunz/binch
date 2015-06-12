import urwid
from disassemble import *
from assembler import *
from statusbar import *
import signals
import traceback

class DisassembleText(urwid.Text):

    def selectable(self):
        return False

    def keypress(self, size, key):
        return key

class DisassembleInstruction(urwid.WidgetWrap):
    def __init__(self, instrSet, da, view):
        urwid.WidgetWrap.__init__(self, None)
        instr = instrSet[0]
        self.isThumb = instrSet[1]
        self.address = urwid.Text(hex(instr.address).rstrip('L'))
        self.opcode = urwid.Text(' '.join(["%02x" % (j) for j in instr.bytes]))
        self.instr = urwid.Text(instr.mnemonic)
        self.operands = urwid.Text(instr.op_str)
        self.editMode = False
        self.hexEditMode = False
        self.da = da
        self.view = view
        self.mode_plain()

    def selectable(self):
        return True

    def mode_plain(self):
        self._w = urwid.Columns([
            ('fixed', 12, self.address),
            ('fixed', 25, self.opcode),
            ('fixed', 10, self.instr),
            ('fixed', 55, self.operands)
            ])
        self._w = urwid.AttrMap(self._w, 'bg', 'reveal focus')

    def mode_edit1(self):
        self._w = urwid.Columns([
            ('fixed', 12, self.address),
            ('fixed', 25, self.opcode),
            ('fixed', 65, self._editbox),
            ])
        self._w = urwid.AttrMap(self._w, 'bg', 'reveal focus')

    def mode_edit2(self):
        self._w = urwid.Columns([
            ('fixed', 12, self.address),
            ('fixed', 25, self._hexeditbox),
            ('fixed', 10, self.instr),
            ('fixed', 55, self.operands)
            ])
        self._w = urwid.AttrMap(self._w, 'bg', 'reveal focus')

    def modifyOpcode(self, opcode):
        if opcode == "":
            self.mode4()
            return

        original_opcode_len = len(self.opcode.text.replace(' ','').decode('hex'))
        if len(opcode) < original_opcode_len:
            if self.da.arch == 'ARM':
                opcode = opcode.ljust(original_opcode_len, "\x00") # Fill with nop
            else:
                opcode = opcode.ljust(original_opcode_len, "\x90") # Fill with nop
        elif len(opcode) > original_opcode_len:
            safe_opcode_len = 0
            opcode_data = self.da.readMemory(int(self.address.text, 16), 0x20)
            if self.isThumb:
                disasm_code = self.da.t_md.disasm(opcode_data, 0x20)
            else:
                disasm_code = self.da.md.disasm(opcode_data, 0x20)
            for i in disasm_code:
                if len(opcode) > safe_opcode_len:
                    safe_opcode_len += len(i.bytes)
            if self.da.arch == 'ARM':
                opcode = opcode.ljust(safe_opcode_len, "\x00") # Fill with nop
            else:
                opcode = opcode.ljust(safe_opcode_len, "\x90") # Fill with nop

        self.da.writeMemory(int(self.address.text, 16), opcode)

        if original_opcode_len == len(opcode):
            self.opcode.set_text(' '.join(["%02x" % ord(i) for i in opcode]))
            if self.isThumb:
                code = [i for i in self.da.t_md.disasm(opcode, len(opcode))][0]
            else:
                code = [i for i in self.da.md.disasm(opcode, len(opcode))][0]
            self.instr.set_text(code.mnemonic)
            self.operands.set_text(code.op_str)
            self.mode_plain()
        else:
            self.view.updateList(self.view.disasmlist._w.focus_position)

    def keypress(self, size, key):
        if self.editMode:
            if key == "esc":
                self.editMode = False
                self.mode_plain()
            elif key == "enter":
                self.editMode = False
                asmcode = self._editbox.get_edit_text()
                if self.da.arch == 'ARM':
                    if self.isThumb:
                        opcode = assemble(asmcode, 'thumb', self.da.arm_arch)
                    else:
                        opcode = assemble(asmcode, self.da.arch, self.da.arm_arch)
                else:
                    opcode = assemble(asmcode, self.da.arch)
                self.modifyOpcode(opcode)
            elif isinstance(key, basestring):
                self._w.keypress(size, key)
            else:
                return key
        elif self.hexEditMode:
            if key == "esc":
                self.hexEditMode = False
                self.mode_plain()
            elif key == "enter":
                self.hexEditMode = False
                hexcode = self._hexeditbox.get_edit_text()
                try:
                    opcode = hexcode.replace(' ','').decode('hex')
                    self.modifyOpcode(opcode)
                except Exception, e:
                    msg = "Error: "+str(e)
                    signals.set_message.send(0, message=msg, expire=2)
                    self.mode_plain()

            elif isinstance(key, basestring):
                self._w.keypress(size, key)
            else:
                return key
        else:
            if key == "enter":
                self._editbox = urwid.Edit("", self.instr.text+" "+self.operands.text)
                self.mode_edit1()
                self.editMode = True
            elif key == "h":
                self._hexeditbox = urwid.Edit("", self.opcode.text)
                self.mode_edit2()
                self.hexEditMode = True
            elif key == "d" or key == "D":
                def fillWithNop(yn, arg):
                    if yn == 'y':
                        if self.da.arch == 'ARM':
                            self.modifyOpcode("\x00")
                        else:
                            self.modifyOpcode("\x90")
                signals.set_prompt_yn.send(self, text="Remove this line?", callback=fillWithNop, arg=None)
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
        self.updateList(dList)

    def set_focus(self, idx):
        self._w.set_focus(idx)

    def updateList(self, dList, focus=0):
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

        self.da = Disassembler(filename)

        items = self.setupList()
        self.disasmlist = DisassembleList(items)
        start_index = self.findIndex(self.da.entry)
        if start_index != -1:
            self.disasmlist.set_focus(start_index)

        self.body = urwid.Padding(self.disasmlist, 'center', 105)
        self.body = urwid.Filler(self.body, ('fixed top',1), ('fixed bottom',1))

        self.footer = StatusBar("HotKeys -> g: Go to a address | s: Save | d: Remove | enter: Modify | q: Quit", self)
        self.view = DisassembleWindow(self,
                urwid.AttrWrap(self.body, 'body'),
                urwid.AttrWrap(self.header, 'head'),
                self.footer)

        signals.call_delay.connect(self.sig_call_delay)

    def findIndex(self, address):
        try:
            if self.da.isThumb(address):
                return self.index_map[address & -2]
            else:
                return self.index_map[address]
        except KeyError:
            return -1

    def setupList(self):
        body = self.da.disasm(self.da.text_addr)
        items = []
        idx = 0
        self.index_map = dict()
        for i, isThumb in body:
            address = i.address
            if address in self.da.symtab:
                items.append(SymbolText(" "))
                items.append(SymbolText(" < "+self.da.symtab[address]+" >"))
                idx+=2
            elif (isThumb and (address - 1) in self.da.symtab):
                items.append(SymbolText(" "))
                items.append(SymbolText(" < "+self.da.symtab[address - 1]+" >"))
                idx+=2
            items.append(DisassembleInstruction((i, isThumb), self.da, self))
            self.index_map[address] = idx
            idx+=1

        return items

    def updateList(self, focus=0):
        items = self.setupList()
        self.disasmlist.updateList(items, focus)

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
                self.disasmlist.set_focus(self.index_map[address])
                return "Jump to "+hex(address)
            else:
                for i in range(1, 0x10):
                    if address - i in self.index_map:
                        self.disasmlist.set_focus(self.index_map[address - i])
                        return "Jump to "+hex(address - i)
                    elif address + i in self.index_map:
                        self.disasmlist.set_focus(self.index_map[address + i])
                        return "Jump to "+hex(address + i)

                return "Invalid address: "+hex(address)

        if k in ('q', 'Q'):
            def askQuit(yn, arg):
                if yn == 'y':
                    raise urwid.ExitMainLoop()
            signals.set_prompt_yn.send(self, text="Quit?", callback=askQuit, arg=None)
        elif k in ('g', 'G'):
            signals.set_prompt.send(self, text="Goto: ", callback=goto)
        elif k in ('s', 'S'):
            self.da.save()

    def sig_call_delay(self, sender, seconds, callback):
        def cb(*_):
            return callback()
        self.loop.set_alarm_in(seconds, cb)
