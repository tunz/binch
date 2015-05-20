import urwid
from disassemble import *
from statusbar import *
import signals

class DisassembleText(urwid.Text):

    def selectable(self):
        return True

    def keypress(self, size, key):
        if key == "j":
            key = "down"
        if key == "k":
            key = "up"
        return key

class SymbolText(urwid.Text):

    def selectable(self):
        return False

    def keypress(self, size, key):
        return key

class DisassembleList(urwid.SimpleListWalker):

    def selectable(self):
        return True

    def keypress(self, size, key):
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

    def keypress(self, size, k):
        k = super(self.__class__, self).keypress(size, k)
        return k

class DisassembleView:
    palette = [('header', 'white', 'black'),
            ('reveal focus', 'black', 'light gray', 'standout'),
            ('status', 'white', 'dark blue', 'standout')]

    def __init__(self, filename):
        self.header = urwid.Text(filename)

        self.da = Disassembler(filename)
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
            items.append(urwid.Columns(
                        [('fixed', 12, DisassembleText(i.split('\t')[0])),
                            ('fixed', 25, DisassembleText(i.split('\t')[1])),
                            ('fixed', 10, DisassembleText(i.split('\t')[2])),
                            DisassembleText(i.split('\t')[3])]))
            self.index_map[address] = idx
            idx+=1

        items = map(lambda x: urwid.AttrMap(x, 'bg', 'reveal focus'), items)
        walker = DisassembleList(items)

        self.disasmlist = urwid.ListBox(walker)
        self.body = urwid.Padding(self.disasmlist, ('fixed left',2), ('fixed right',1))
        self.body = urwid.Filler(self.body, ('fixed top',1), ('fixed bottom',1))

        self.footer = StatusBar("status bar")
        self.view = DisassembleWindow(self,
                urwid.AttrWrap(self.body, 'body'),
                urwid.AttrWrap(self.header, 'head'),
                self.footer)

        signals.call_delay.connect(self.sig_call_delay)

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
                return "Invalid address: "+hex(address)

        if k in ('q', 'Q'):
            raise urwid.ExitMainLoop()
        if k in ('g', 'G'):
            signals.set_prompt.send(self, text="Goto: ", callback=goto)

    def sig_call_delay(self, sender, seconds, callback):
        def cb(*_):
            return callback()
        self.loop.set_alarm_in(seconds, cb)
