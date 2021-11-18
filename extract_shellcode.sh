#!/bin/bash

# Author:   VPR
# Created:  11/17/2021
# Modified: 11/17/2021
#
# Brief:
#   extracts shellcode from target file and outputs it to either
#   a specified file_path, or a default file path (out.bin)

set -e

USAGE_STR="Usage Error: $0 [ path/to/target ] [-o output ]"

DEFAULT_PATH="${PWD}"
DEFAULT_FILE="out.bin"
DEFAULT_FILE_PATH="${PWD}/out.bin"

TARGET=$1
OUTPUT_PATH="${DEFAULT_FILE_PATH}"

if [ $# -lt 1 ];
then
    echo "${USAGE_STR}" >&2
    exit 1
fi

while getopts 'o:' OPTION;
do
    case "$OPTION" in
        o)
            OUTPUT_PATH="$OPTARG"
            ;;
        *)
            echo "${USAGE_STR}" >&2
        ;;
    esac
done

__once=1;
for byte in $(objdump -d ${TARGET} | grep "^ " | cut -f2);
do
    if [ $__once -eq 1 ];
    then
        echo -ne '\x'$byte > ${OUTPUT_PATH};
        __once=0;
    else
        echo -ne '\x'$byte >> ${OUTPUT_PATH};
    fi
done;

if [ -f ${TARGET} ];
then
    echo "bytes written to '${OUTPUT_PATH}'"
fi
