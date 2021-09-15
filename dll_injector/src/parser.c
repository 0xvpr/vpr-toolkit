#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
#endif

#include "parser.h"
#include "util.h"
#include <windows.h>
#include <stdio.h>

int ParseCommandLine(int argc, char** argv, unsigned* time_ms)
{
    int operation = 0;
    int i = argc-1;

    if (argc < 3)
        __usage_error("Missing positional arguments", argv[0]);

    while (i > 3)
    {
        if (argv[i][0] == '-')
        {
            switch (argv[i][1])
            {
                case 'd':
                {
                    if (i < argc - 1)
                        sscanf(argv[i+1], "%d", time_ms);
                    else
                        __usage_error("-d switch used incorrectly", argv[0]);

                    if (!time_ms)
                        __usage_error("-d switch used incorrectly", argv[0]);

                    break;
                }
                case 'i':
                {
                    char arg_to_parse[32] = { 0 };
                    if (i < argc - 1)
                        strncpy_s(arg_to_parse, sizeof(arg_to_parse), argv[i+1], sizeof(arg_to_parse));
                    
                    if (!strncmp(arg_to_parse, "LoadLibraryA", strlen("LoadLibraryA")))
                        operation |= INJECT_LOAD_LIBRARY_A;
                    else
                        __usage_error("Unsupported injection method", argv[0]);

                    break;
                }
                default:
                    break;
            }
        }
        i--;
    }

    return operation;
}
