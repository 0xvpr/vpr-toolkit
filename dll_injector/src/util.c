#include "util.h"
#include <stdio.h>
#include <stdlib.h>

void __usage_error(const char* msg, char* argv_0)
{
    fprintf(stderr,
        "Error message: %s.\n\n"
        "Usage: %s <target_process> <path/to/dll> [ -d ] [ -i ]\n\n"
        "positional arguments:\n"
        " target_process, path/to/dll\n\n"
        "optional arguments:\n"
        " -d,\tadd delay to the injection (miliseconds)\n"
        " -i,\tspecify injection method\n\n"
        "example:\n"
        " dll_injector32.exe calc.exe ./payload.dll -i LoadLibraryA -d 2000\n"
        , msg, argv_0
    );

    exit(1);
}
