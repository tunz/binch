
import os
from subprocess import Popen, PIPE
import signals
import re

def assemble(code, arch):

    asm_fd = open('.asm', 'w')
    asm_fd.write(code)
    asm_fd.close()

    llvm_arch = {'x86':'x86','x64': 'x86-64'}[arch]

    p = Popen(['llvm-mc',
        '-x86-asm-syntax=intel',
        '-arch=%s' % (llvm_arch),
        '-assemble',
        '-o','.binary',
        '-show-encoding',
        '.asm'
        ], stderr=PIPE)
    p.wait()

    err = p.stderr.read()
    if len(err) > 0:
        msg = "Error: "+err.strip()
        signals.set_message.send(0, message=msg, expire=2)
        return ""

    os.remove('.asm')

    data = open('.binary','r').read()
    s = re.search("encoding: \[(.*)\]",data)
    opcode = ''.join([chr(int(i,16)) for i in s.group(1).split(',')])

    os.remove('.binary')

    return opcode
