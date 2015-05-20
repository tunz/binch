import urwid
import signals

class CommandLine(urwid.WidgetWrap):
    def __init__(self):
        urwid.WidgetWrap.__init__(self, None)
        self.clear()
        signals.set_prompt.connect(self.sig_prompt)
        signals.set_message.connect(self.sig_message)
        self.promptCallback = False

    def clear(self):
        self._w = urwid.Text("")

    def sig_message(self, sender, message, expire=None):
        w = urwid.Text(message)
        self._w = w
        if expire:
            def cb(*args):
                if w == self._w:
                    self.clear()
            signals.call_delay.send(seconds=expire, callback=cb)

    def sig_prompt(self, sender, text, callback):
        signals.focus.send(self, section='footer')
        self._w = urwid.Edit(text, "")
        self.promptCallback = callback

    def prompt(self, text):
        msg = self.promptCallback(text)
        signals.focus.send(self, section='body')
        self.promptCallback = False
        signals.set_message.send(self, message=msg, expire=1)

    def prompt_clear(self):
        self.promptCallback = False
        signals.focus.send(self, section='body')
        self.clear()

    def selectable(self):
        return True

    def keypress(self, size, k):
        if self.promptCallback:
            if k == "esc":
                self.prompt_clear()
            elif k == "enter":
                self.prompt(self._w.get_edit_text())
            elif isinstance(k, basestring):
                self._w.keypress(size, k)
            else:
                return k

class StatusBar(urwid.WidgetWrap):
    def __init__(self, text):
        urwid.WidgetWrap.__init__(self, None)
        self.commandline = CommandLine() 
        self.status = urwid.WidgetWrap(urwid.Text(text))
        self.status = urwid.AttrMap(self.status, 'status')
        self._w = urwid.Pile([self.status, self.commandline])

    def keypress(self, *args, **kwargs):
        return self.commandline.keypress(*args, **kwargs)

    def selectable(self):
        return True
