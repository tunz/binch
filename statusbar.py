import urwid

class CommandLine(urwid.WidgetWrap):
    def __init__(self):
        urwid.WidgetWrap.__init__(self,None)
        self._w = urwid.Text("")
        #self.clear()

    def selectable(self):
        return True

    def keypress(self, size, k):
        return k

class StatusBar(urwid.WidgetWrap):
    #def __init__(self, master, text):
    def __init__(self, text):
        self.commandline = CommandLine() 
        self.status = urwid.WidgetWrap(urwid.Text(text))
        self.status = urwid.AttrMap(self.status, 'status')
        self._w = urwid.Pile([self.status, self.commandline])

    def keypress(self, *args, **kwargs):
        return self.commandline.keypress(*args, **kwargs)

    def selectable(self):
        return True
