#!/usr/bin/env python3

"""
Author:   VPR
Created:  September 13, 2021
Modified: September 14, 2021
"""

import os
import sys
import argparse
import platform
import subprocess

from typing import Tuple
from typing import NoReturn
from argparse import Namespace
from argparse import ArgumentParser

PRINT_TO_STDOUT = 1
SAVE_TO_FILE    = 2

def init_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument(
        "-o", "--output",
        default="",
        dest="dest",
        help="Provide destination of output file.",
        type=str
    )

    return parser

def handle_parser(parser: ArgumentParser) -> Tuple[Namespace, int]:
    operations = 0
    args = parser.parse_args()

    if args.dest == "":
        operations |= PRINT_TO_STDOUT
    else:
        operations |= SAVE_TO_FILE

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


def copy_clipboard(arch: str, args: Namespace, operations: int) -> NoReturn:
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

    # Cleanup output
    stdout = stdout.decode().strip()

    # Handle operations
    if operations & PRINT_TO_STDOUT:
        print(stdout, end="")
        
    if operations & SAVE_TO_FILE:
        with open(f"{args.dest}", "w") as f:
            f.write(stdout)

if __name__ == "__main__":
    parser = init_parser()
    args, operations = handle_parser(parser)

    arch = get_arch() 

    copy_clipboard(arch, args, operations)
