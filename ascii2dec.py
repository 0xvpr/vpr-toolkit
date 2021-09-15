#!/usr/bin/env python3

"""
Author:   VPR
Created:  September 8, 2021
Modified: September 14, 2021
"""

import sys

from typing import List
from typing import NoReturn

def convert_ascii_to_dec(args: List[str]) -> List[str]:
    results = []
    for text in args:
        string = text + ": "
        string += "0x" + "".join([hex(ord(c))[2:] for c in text]).upper()
        results.append(string)

    return results

def display_usage(exit_code: int) -> NoReturn:
    if exit_code == 1:
        sys.stderr.write(f"Usage: {sys.argv[0]} \"Text_1\" \"Text_2\" ...")
    
    sys.exit(exit_code)

if __name__ == "__main__":
    try:
        assert len(sys.argv) > 1
        args = sys.argv[1:]
        results = convert_ascii_to_dec(args)
    except:
        display_usage(1)

    for result in results:
        print(result)
