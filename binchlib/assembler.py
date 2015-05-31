
import os
from subprocess import Popen, PIPE, call
import signals
import re

def cmd_exists(cmd):
    return call("type "+cmd, shell=True, stdout=PIPE, stderr=PIPE) == 0

def assemble(code, arch, arm_arch=None):

    if cmd_exists("llvm-mc"):

        asm_fd = open('.asm', 'w')
        asm_fd.write(code)
        asm_fd.close()

        llvm_arch = {'x86':'x86','x64':'x86-64','ARM':'arm','thumb':'thumb'}[arch]

        args = ['llvm-mc',
            '-assemble',
            '-o','.opcode',
            '-show-encoding',
            '.asm'
            ]

        if arm_arch:
            args.append('--triple=%s%s' % (llvm_arch, arm_arch))
        else:
            args.append('-arch=%s' % (llvm_arch))

        if arch in ['x86', 'x64']:
            args.append('-x86-asm-syntax=intel')

        p = Popen(args, stderr=PIPE)
        p.wait()

        err = p.stderr.read()
        if len(err) > 0:
            os.remove('.asm')
            msg = "Error: "+err.strip()
            signals.set_message.send(0, message=msg, expire=2)
            return ""

        data = open('.opcode','r').read()
        s = re.search("encoding: \[(.*)\]",data)
        if s:
            opcode = ''.join([chr(int(i,16)) for i in s.group(1).split(',')])
        else:
            msg = "Error: No assembled code"
            signals.set_message.send(0, message=msg, expire=2)
            return ""

    elif cmd_exists("nasm"):

        msg = "Warning: Please use llvm-mc, instead of nasm."
        signals.set_message.send(0, message=msg, expire=2)

        asm_fd = open('.asm', 'w')

        bit = {'x86':32,'x64': 64}[arch]
        asm_fd.write("bits %d\n" % (bit))

        # TODO: Support rip
        if "ptr" in code:
            if code.startswith("lea"):
                code = re.sub(r'(qword|dword|word|byte) ptr ','', code)
            else:
                code = code.replace('ptr ','')
        asm_fd.write(code)
        asm_fd.close()

        p = Popen(['nasm','-f','bin','-o','.opcode','.asm'], stderr=PIPE)
        p.wait()
        err = p.stderr.read()
        if len(err) > 0:
            os.remove('.asm')
            msg = "Error: "+err.strip()
            signals.set_message.send(0, message=msg, expire=2)
            return ""

        opcode = open('.opcode','rb').read()

    os.remove('.asm')
    os.remove('.opcode')

    return opcode
