#!/usr/bin/env python3

"""
Author:   VPR
Created:  September 12, 2021
Modified: November 17, 2021

Description:
    Takes in a given file and returns a specified format of either
    a c-style string array or a raw backslash escaped hex string.
"""

import pathlib
import sys

from argparse import ArgumentParser
from typing import ByteString, NoReturn, Union, Tuple

OP_RAWSTR = 1
OP_CSTR   = 2

def __usage_error(exit_code: int) -> NoReturn:
    if exit_code == 1:
        sys.stderr.write(f"Usage: {sys.argv[0]} \"path/to/image\"\n\n")
    elif exit_code == 2:
        sys.stderr.write(f"Too many arguments.\n")
    elif exit_code == 3:
        sys.stderr.write(f"Argument is NOT a file.\n")
    elif exit_code == 4:
        sys.stderr.write(f"File not found\n")
    elif exit_code == 5:
        sys.stderr.write(f"File is empty\n")

    sys.stderr.write(f"Exited with exit code: {exit_code}.")
    sys.exit(exit_code)

def handle_command_line() -> Union[Tuple[str, ByteString], NoReturn]:
    argc = len(sys.argv)
    argv = sys.argv

    if argc < 2:
        __usage_error(1) # not enough arguments

    if argc > 3:
        __usage_error(2) # only specify one switch pls

    defined_args = ( argv[0], "-c", "--cstr", "-r", "--rawstr" )
    filtered_path = list(filter(lambda x: True if x not in defined_args else False, argv))
    file_path = filtered_path[0]

    try:
        if pathlib.Path(file_path).is_file() is False:
            __usage_error(2)

    except FileNotFoundError:
        __usage_error(3)

    try:
        file_name = file_path.strip()
        with open(file_path, "rb") as f:
            bytes_string = f.read()
            assert len(bytes_string) > 0

    except AssertionError:
        __usage_error(4)

    return ( file_name, bytes_string )

def init_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument(
        "-r", "--rawstr",
        action="store_true",
        dest="rawstr",
        help="Convert bytes in file to raw string.",
    )
    parser.add_argument(
        "-c", "--cstr",
        action="store_true",
        dest="cstr",
        help="Convert bytes in file to cstr.",
    )
    parser.add_argument(
        nargs='?',
        default="",
        dest="file_path",
        help="path/to/file.txt",
        type=str
    )

    return parser

def handle_parser(parser: ArgumentParser) -> int:
    operation = OP_RAWSTR
    args = parser.parse_args()

    if args.rawstr is True:
        operation = OP_RAWSTR
    elif args.cstr is True:
        operation = OP_CSTR

    return operation

def convert_file_to_rawstr(byte_string: ByteString) -> str:
    result = '"'

    for byte in byte_string:
        if byte < 0x10:
            result += "\\x0" + hex(byte)[2:].upper()
        else:
            result += "\\x" + hex(byte)[2:].upper()

    return result + '"'

def convert_file_to_cstr(file_name: str, byte_string: ByteString) -> str:
    # Remove bad characters
    bad_chars = { ord(x) : ord("_") for x in "[~`!@#$%^&*()-_=+[{]}\\|:;.'<,>/?\"]" }
    clean_name = file_name.translate(bad_chars).lower()
    
    # Add prefix
    result = f"unsigned char {clean_name}[{len(byte_string)}] = {'{'}"

    # Set elements per row
    breakline = 10
    for i, byte in enumerate(byte_string):
        if (i % breakline) == 0:
            result += "\n    "
        if byte <= 0xF:
            result += "0x0" + hex(byte)[2:].upper()
        else:
            result += "0x" + hex(byte)[2:].upper()
        result += ", "

    return result[:-2] + "\n};"

if __name__ == "__main__":
    file_name, byte_string = handle_command_line()

    parser = init_parser()
    operation = handle_parser(parser)

    if not operation: # Default to raw string
        print(convert_file_to_rawstr(byte_string))

    elif operation == OP_RAWSTR:
        print(convert_file_to_rawstr(byte_string))

    elif operation == OP_CSTR:
        print(convert_file_to_cstr(file_name, byte_string))
