
import os
from subprocess import Popen, PIPE

def assemble(code, arch):

    asm_fd = open('.asm', 'w')

    bit = {'x86':32,'x64': 64}[arch]
    asm_fd.write("bits %d\n" % (bit))
    
    # TODO: Support rip
    asm_fd.write(code)
    asm_fd.close()

    p = Popen(['nasm','-f','bin','-o','.opcode','.asm'], stderr=PIPE)
    p.wait()
    err = p.stderr.readline()
    if len(err) > 0:
        return "Error: "+err

    os.remove('.asm')
    opcode_fd = open('.opcode','rb')
    opcode = opcode_fd.read()
    opcode_fd.close()
    os.remove('.opcode')

    return opcode
