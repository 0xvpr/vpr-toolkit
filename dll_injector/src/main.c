/**
 * Author:   VPR
 * Created:  September 14, 2021
 * Modified: September 17, 2021
**/

#include "manualmap.h"
#include "injector.h"
#include "parser.h"
#include <stdio.h>

int main(int argc, char* argv[])
{
    int inject_status = 0;
    unsigned delay_ms = 0;
    DWORD process_id = 0;

    int operation = ParseCommandLine(argc, argv, &delay_ms);
    const char* target_process = argv[1];
    const char* dll_rel_path = argv[2];

    printf("Searching for %s...\n", target_process);
    while (!process_id)
    {
        process_id = GetProcessIdByProcessName(target_process);
    }
    printf("%s Found.\n\n", target_process);

    if (delay_ms)
    {
        printf("Delay(ms): %d\n\n", delay_ms);
        Sleep(delay_ms);
    }

    if (operation & INJECT_LOAD_LIBRARY_A)
        inject_status = inject_LoadLibraryA(process_id, dll_rel_path);
    else if (operation & INJECT_MANUAL_MAP)
        inject_status = inject_ManualMap(process_id, dll_rel_path);

    if (inject_status)
        __handle_error(inject_status);
    printf("Injection: %s.\n", (inject_status ? "Failed" : "Successful"));

    return inject_status;
}
