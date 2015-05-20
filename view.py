import urwid
from disassemble import *
from statusbar import *

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

class DisassembleView:
    palette = [('header', 'white', 'black'),
            ('reveal focus', 'black', 'light gray', 'standout'),
            ('status', 'white', 'dark blue', 'standout')]

    def __init__(self, filename):
        self.header = urwid.Text(filename)

        da = Disassembler(filename)
        body = da.disasm(da.entry)
        items = []
        for i in body:
            address = int(i.split('\t')[0].lstrip('0x'),16)
            if address in da.symtab:
                items.append(SymbolText(" "))
                items.append(SymbolText(" < "+da.symtab[address]+" >"))
            items.append(urwid.Columns(
                        [('fixed', 12, DisassembleText(i.split('\t')[0])),
                            ('fixed', 25, DisassembleText(i.split('\t')[1])),
                            ('fixed', 10, DisassembleText(i.split('\t')[2])),
                            DisassembleText(i.split('\t')[3])]))

        items = map(lambda x: urwid.AttrMap(x, 'bg', 'reveal focus'), items)
        walker = DisassembleList(items)

        self.leftListbox = urwid.ListBox(walker)
        self.leftListbox = urwid.Padding(self.leftListbox, ('fixed left',2), ('fixed right',1))
        self.leftListbox = urwid.Filler(self.leftListbox, ('fixed top',1), ('fixed bottom',1))

        self.rightListbox = urwid.ListBox([DisassembleText('test')])
        self.rightListbox = urwid.Padding(self.rightListbox, ('fixed left',1), ('fixed right',2))
        self.rightListbox = urwid.Filler(self.rightListbox, ('fixed top',1), ('fixed bottom',1))

        self.body = urwid.Columns([('fixed', 100, self.leftListbox), ('fixed', 1, urwid.SolidFill("|")), self.rightListbox])

        self.footer = StatusBar("status bar")
        self.view = urwid.Frame(
                urwid.AttrWrap(self.body, 'body'),
                header=urwid.AttrWrap(self.header, 'head'),
                footer=self.footer)

    def main(self):
        self.loop = urwid.MainLoop(self.view, self.palette,
                handle_mouse=False,
                unhandled_input=self.unhandled_input)
        self.loop.run()

    def unhandled_input(self, k):
        if k in ('q', 'Q'):
            raise urwid.ExitMainLoop()
        #if k in ('g', 'G'):
