#!/usr/bin/env python3

# Creator:          VPR
# Created:          May 6th, 2023
# Updated:          June 12th, 2023

import argparse
import sys
import os

from enum import Enum
from dataclasses import dataclass

class ToolType(Enum):
    binary   = ( 1 << 0 )
    script   = ( 1 << 1 )
    template = ( 1 << 2 )

@dataclass
class Tool(object):
    _project_url     :    str
    _type            :    ToolType

def download_toolkit() -> int:
    """
    """

    tool_kit = [
        Tool( "vpr-shell-shock" , ToolType.template ),
        Tool( "vpr-omega-zero"  , ToolType.binary   ),
        Tool( "vpr-overwatch"   , ToolType.binary   ),
        Tool( "vpr-pidjeon"     , ToolType.binary   ),
        Tool( "vpr-extract"     , ToolType.binary   ),
        Tool( "vpr-bin2fmt"     , ToolType.binary   ),
        Tool( "vpr-midas"       , ToolType.binary   ),
    ]

    for tool in tool_kit:
        print(tool)
        # Download latest binaries
        if tool._type == ToolType.binary or tool._type == ToolType.script:
            os.system(f"curl -LJO --output-dir vpr-toolkit $(curl -s https://api.github.com/repos/0xvpr/{tool._project_url}/releases/latest | grep 'browser_download_url' | cut -d '\"' -f 4)")

        if tool._type == ToolType.template:
            os.system(f"git clone https://github.com/0xvpr/{tool._project_url} vpr-toolkit/{tool._project_url}")

    return 0

if __name__ == "__main__":
    # Handle arguments
    # Set toolkit dir
    # Install?

    os.system("mkdir vpr-toolkit")
    download_toolkit()
