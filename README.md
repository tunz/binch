# a light BINary patCH tool
A light ELF binary patch tool in python urwid. It helps to patch a ELF binary in a few steps.

![capture](./img/screenshot.png)

Now, it only supports x86, x86_64, and ARM(experimental).

## Usage

```
$ ./binch [binary name]
```

#### Shortcuts
```
g: Go to a specific address. (if not exists, jump to nearest address)
d: Remove a current line. (Fill with nop)
q: Quit.
s: Save a modified binary to a file.
enter: Modify a current line.
h: Modify hex bytes of a current line.
```

## Dependencies
```
# pip install pyelftools
# pip install capstone
# pip install urwid
# pip install blinker
```

For llvm-mc (Ubuntu)
```
# apt-get install llvm
```
or (OS X)
```
# port install llvm-3.6
# ln -s /opt/local/bin/llvm-mc-mp-3.6 /opt/local/bin/llvm-mc
```
