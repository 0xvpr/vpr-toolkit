#!/usr/bin/env python3

"""
Author:   VPR
Created:  September 13, 2021
Modified: September 14, 2021

Version: 0.5
"""

import os
import sys
import argparse
import platform
import subprocess

from typing import List
from typing import Tuple
from typing import NoReturn
from argparse import Namespace
from argparse import ArgumentParser

OP_PRINT_TO_STDOUT = 0x01
OP_SAVE_TO_FILE    = 0x02
OP_DELIMITER       = 0x04
OP_PREFIX          = 0x08
OP_SUFFIX          = 0x10
OP_STRIP           = 0x20

def init_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument(
        "-o", "--output",
        default="",
        dest="dest",
        help="Provide destination of output file.",
        type=str
    )
    parser.add_argument(
        "-d", "--delimiter",
        default="",
        dest="delimiter",
        help="Provide a pattern that will be stripped from the left of each line",
        type=str
    )
    parser.add_argument(
        "-i", "-p", "--prefix",
        default="",
        dest="prefix",
        help="Provide a pattern that will be inserted to the left of each line",
        type=str
    )
    parser.add_argument(
        "-a", "--append", "--suffix",
        default="",
        dest="suffix",
        help="Provide a pattern that will be appended to the right of each line",
        type=str
    )
    parser.add_argument(
        "-r", "-s", "--remove", "--strip",
        default="",
        dest="strip",
        help="Provide a pattern that will be stripped at every occurrence",
        type=str
    )

    return parser

def handle_parser(parser: ArgumentParser) -> Tuple[Namespace, int]:
    operations = OP_PRINT_TO_STDOUT
    args = parser.parse_args()

    if args.dest != "":
        operations |= OP_SAVE_TO_FILE

    if args.delimiter != "":
        operations |= OP_DELIMITER

    if args.prefix != "":
        operations |= OP_PREFIX

    if args.suffix != "":
        operations |= OP_SUFFIX

    if args.strip != "":
        operations |= OP_STRIP

    return ( args, operations )

def get_arch() -> str:
    if platform.system() == "Windows":
        return "Windows"
    elif platform.system() == "Linux":
        if "Microsoft" in os.uname().version:
            return "WSL"
        else:
            return "Linux"
    else:
        return "Unsupported OS"


def get_clipboard_contents(arch: str, operations: int) -> List[str]:
    stdout = b""
    if arch == "WSL":
        p = subprocess.Popen("Get-Clipboard", 1024, "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout, _ = p.communicate()
        p.wait()
    elif arch == "Linux":
        p = subprocess.Popen("-o", 1024, "xclip",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout, _ = p.communicate()
        p.wait()
    elif arch == "Windows":
        p = subprocess.Popen("Get-Clipboard", 1024, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout, _ = p.communicate()
        p.wait()

    else:
        sys.stderr.write(f"Unsupported OS: {platform.system}\n\nExit code: 1")
        sys.exit(1)

    # Cleanup output and split
    stdout_split = stdout.decode().strip().replace("\r\n", "\n").split("\n")

    return stdout_split

def execute_operations(stdout_split: List[str], args: ArgumentParser) -> NoReturn:
    if operations & OP_DELIMITER:
        new_stdout = [ ]

        delim = args.delimiter
        for line in stdout_split:
            new_stdout.append( line.lstrip(delim).lstrip() )

        stdout_split = new_stdout
        
    if operations & OP_PREFIX:
        new_stdout = [ ]

        prefix = args.prefix
        for line in stdout_split:
            new_stdout.append( prefix + line )

        stdout_split = new_stdout
        
    if operations & OP_SUFFIX:
        new_stdout = [ ]

        suffix = args.suffix
        for line in stdout_split:
            new_stdout.append( line + suffix )

        stdout_split = new_stdout

    # Final formatting and output
    stdout = "\n".join(stdout_split)
    if operations & OP_PRINT_TO_STDOUT:
        print(stdout, end="")

    if operations & OP_SAVE_TO_FILE:
        with open(f"{args.dest}", "w") as f:
            f.write(stdout)
        

if __name__ == "__main__":
    parser = init_parser()
    args, operations = handle_parser(parser)
    arch = get_arch() 
    stdout_split = get_clipboard_contents(arch, operations)
    
    execute_operations(stdout_split, args)
