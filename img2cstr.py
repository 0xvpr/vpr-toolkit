#!/usr/bin/env python3

"""
Author:   VPR
Created:  September 12, 2021
Modified: September 15, 2021
"""

import sys

from typing import NoReturn
from typing import ByteString

def convert_img_to_cstr(img_name: str, img_bytes: ByteString) -> str:
    result = f"unsigned char {img_name}[{len(img_bytes)}] = " + "{"
    breakline = 10

    for i, byte in enumerate(img_bytes):
        if (i % breakline) == 0:
            result += "\n    "
        if byte <= 0xF:
            result += "0x0" + hex(byte)[2:].upper()
        else:
            result += "0x" + hex(byte)[2:].upper()
        result += ", "

    return result[:-2] + "\n};"

def display_usage(exit_code: int) -> NoReturn:
    if exit_code == 1:
        sys.stderr.write(f"Usage: {sys.argv[0]} \"path/to/image\"\n\n")
    if exit_code == 2:
        sys.stderr.write(f"Not enough bytes in file")

    sys.stderr.write(f"Exited with exit code: {exit_code}.")
    sys.exit(exit_code)

if __name__ == "__main__":
    img_path = ""
    img_name = ""

    try:
        assert len(sys.argv) > 1
        img_path = sys.argv[1]
        img_name = img_path.split('/')[-1].strip().replace('.', '_')
    except:
        display_usage(1)

    try:
        with open(img_path, "rb") as f:
            img_bytes = f.read()
            assert (len(img_bytes) > 1)
    except:
        display_usage(2)

    result = convert_img_to_cstr(img_name, img_bytes)
    print(result)
