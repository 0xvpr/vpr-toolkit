/**
 * Author:   VPR
 * Created:  September 14, 2021
 * Modified: September 14, 2021
**/

#include "injector.h"
#include "parser.h"
#include <stdio.h>

int main(int argc, char* argv[])
{
    unsigned time_ms = 0;
    int repeat = 0;

    // Parse command line arguments
    int operation = ParseCommandLine(argc, argv, &time_ms, &repeat);
    const char* target_process = argv[1];
    const char* dll_path = argv[2];

    // Acquire pid
    DWORD process_id = 0;
    printf("Searching for %s...\n", target_process);
    while (!process_id)
        process_id = GetProcessIdByProcessName(target_process);
    printf("%s Found.\n\n", argv[0]);

    // Delay
    if (time_ms)
    {
        printf("Delay(ms): %d\n\n", time_ms);
        Sleep(time_ms);
    }

    // Injection
    int inject_status = InjectDLL(process_id, dll_path, operation);
    if (inject_status)
        __handle_error(inject_status);
    printf("Injection: %s.\n", (inject_status ? "Failed" : "Successful"));

    return inject_status;
}
