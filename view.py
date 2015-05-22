import urwid
from disassemble import *
from assembler import *
from statusbar import *
import signals

class DisassembleText(urwid.Text):

    def selectable(self):
        return False

    def keypress(self, size, key):
        return key

class DisassembleInstruction(urwid.WidgetWrap):
    def __init__(self, instrSet, da, view):
        urwid.WidgetWrap.__init__(self, None)
        self.address = urwid.Text(instrSet[0])
        self.opcode = urwid.Text(instrSet[1])
        self.instr = urwid.Text(instrSet[2])
        self.operands = urwid.Text(instrSet[3])
        self.editMode = False
        self.da = da
        self.view = view
        self.mode4()

    def selectable(self):
        return True

    def mode4(self):
        self._w = urwid.Columns([
            ('fixed', 12, self.address),
            ('fixed', 25, self.opcode),
            ('fixed', 10, self.instr),
            ('fixed', 55, self.operands)
            ])

    def mode3(self):
        self._w = urwid.Columns([
            ('fixed', 12, self.address),
            ('fixed', 25, self.opcode),
            ('fixed', 65, self._editbox),
            ])

    def keypress(self, size, key):
        if self.editMode:
            if key == "esc":
                self.editMode = False
                self.mode4()
            elif key == "enter":
                self.editMode = False
                asmcode = self._editbox.get_edit_text()
                opcode = assemble(asmcode, self.da.arch)
                if opcode == "":
                    self.mode4()
                    return
                self.da.writeMemory(int(self.address.text, 16), opcode)
                if len(self.opcode.text.replace(' ','').decode('hex')) == len(opcode):
                    self.opcode.set_text(' '.join(["%02x" % ord(i) for i in opcode]))
                    code = [i for i in self.da.md.disasm(opcode, len(opcode))][0]
                    self.instr.set_text(code.mnemonic)
                    self.operands.set_text(code.op_str)
                    self.mode4()
                else:
                    self.view.updateList(self.view.disasmlist._w.focus_position)
            elif isinstance(key, basestring):
                self._w.keypress(size, key)
            else:
                return key
        else:
            if key == "enter":
                self._editbox = urwid.Edit("", self.instr.text+" "+self.operands.text)
                self.mode3()
                self.editMode = True
            else:
                if key == "j":
                    key = "down"
                elif key == "k":
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
        self.header = urwid.Text(" BIP: %s" % (filename))

        self.da = Disassembler(filename)

        items = self.setupList()
        self.disasmlist = DisassembleList(items)

        self.body = urwid.Padding(self.disasmlist, 'center', 105)
        self.body = urwid.Filler(self.body, ('fixed top',1), ('fixed bottom',1))

        self.footer = StatusBar("status bar")
        self.view = DisassembleWindow(self,
                urwid.AttrWrap(self.body, 'body'),
                urwid.AttrWrap(self.header, 'head'),
                self.footer)

        signals.call_delay.connect(self.sig_call_delay)

    def setupList(self):
        body = self.da.disasm(self.da.entry)
        items = []
        idx = 0
        self.index_map = dict()
        for i in body:
            address = int(i.split('\t')[0].lstrip('0x'),16)
            if address in self.da.symtab:
                items.append(SymbolText(" "))
                items.append(SymbolText(" < "+self.da.symtab[address]+" >"))
                idx+=2
            items.append(DisassembleInstruction(i.split('\t'), self.da, self))
            self.index_map[address] = idx
            idx+=1

        items = map(lambda x: urwid.AttrMap(x, 'bg', 'reveal focus'), items)
        return items

    def updateList(self, focus=0):
        items = self.setupList()
        self.disasmlist.updateList(items, focus)

    def main(self):
        self.loop = urwid.MainLoop(self.view, self.palette,
                handle_mouse=False,
                unhandled_input=self.unhandled_input)
        self.loop.run()

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
            raise urwid.ExitMainLoop()
        if k in ('g', 'G'):
            signals.set_prompt.send(self, text="Goto: ", callback=goto)

    def sig_call_delay(self, sender, seconds, callback):
        def cb(*_):
            return callback()
        self.loop.set_alarm_in(seconds, cb)
