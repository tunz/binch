from . import signals
import view
import urwid

class CommandLine(urwid.WidgetWrap):
    def __init__(self):
        urwid.WidgetWrap.__init__(self, None)
        self.clear()
        signals.set_prompt.connect(self.sig_prompt)
        signals.set_prompt_yn.connect(self.sig_prompt_yn)
        signals.set_message.connect(self.sig_message)
        self.prompt_callback = False
        self.prompt_yn_callback = False

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
        self.prompt_yn_callback = False
        signals.focus.send(self, section='footer')
        self._w = urwid.Edit(text, "")
        self.prompt_callback = callback

    def sig_prompt_yn(self, sender, text, callback, arg):
        self.prompt_callback = False
        signals.focus.send(self, section='footer')
        self.ask_yn(text, callback, arg)

    def ask_yn(self, text, callback, arg):
        self._w = urwid.Edit(text + " (y/n):", '')
        self.prompt_yn_callback = (callback, arg)

    def prompt(self, text):
        msg = self.prompt_callback(text)
        self.prompt_callback = False
        if isinstance(msg, tuple):
            msg, callback, arg = msg
            self.ask_yn(msg, callback, arg)
        else:
            signals.focus.send(self, section='body')
            if isinstance(msg, str):
                signals.set_message.send(self, message=msg, expire=1)

    def prompt_yn(self, yn):
        func, arg = self.prompt_yn_callback
        msg = func(yn, arg)
        signals.focus.send(self, section='body')
        self.prompt_yn_callback = False
        if msg:
            signals.set_message.send(self, message=msg, expire=1)
        else:
            self.clear()

    def prompt_clear(self):
        self.prompt_callback = False
        self.prompt_yn_callback = False
        signals.focus.send(self, section='body')
        self.clear()

    def selectable(self):
        return True

    def keypress(self, size, k):
        if self.prompt_callback:
            if k == "esc":
                self.prompt_clear()
            elif k == "enter":
                self.prompt(self._w.get_edit_text())
            elif isinstance(k, basestring):
                self._w.keypress(size, k)
            else:
                return k
        elif self.prompt_yn_callback:
            if k == "esc":
                self.prompt_clear()
            elif k == "y" or k == "Y":
                self.prompt_yn('y')
            elif k == "n" or k == "N":
                self.prompt_yn('n')

class StatusBar(urwid.WidgetWrap):
    def __init__(self, text, view):
        urwid.WidgetWrap.__init__(self, None)
        self.view = view
        self.commandline = CommandLine()
        self.default_text = text
        self.update_status()
        signals.redraw_status.connect(self.sig_redraw_status)

    def sig_redraw_status(self, sender):
        self.update_status()

    def update_status(self):
        if self.view.disasmblr.arch == 'ARM' and isinstance(self.view.disasmlist._w.focus, view.DisassembleInstruction):
            if self.view.disasmlist._w.focus.isthumb:
                mode = "[Thumb]"
            else:
                mode = "[ ARM ]"
            self.status = urwid.Columns([
                urwid.WidgetWrap(urwid.Text(self.default_text)),
                ('fixed', 20, urwid.WidgetWrap(urwid.Text(mode)))
                ])
        else:
            self.status = urwid.WidgetWrap(urwid.Text(self.default_text))
        self.status = urwid.AttrMap(self.status, 'status')
        self._w = urwid.Pile([self.status, self.commandline])

    def keypress(self, *args, **kwargs):
        return self.commandline.keypress(*args, **kwargs)

    def selectable(self):
        return True
