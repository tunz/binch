#!/usr/bin/env python

from view import DisassembleView
import argparse
import sys
import os

def binch(args=None):
    parser = argparse.ArgumentParser(description='A light ELF binary patch tool.')
    parser.add_argument('filename', metavar='filename', type=str,
                               help='a binary filename to patch')
    args = parser.parse_args()

    filepath = os.path.abspath(args.filename)

    if os.path.isfile(filepath):
        DisassembleView(filepath).main()
    else:
        print "[-] There is no file: %s" % (filepath)
