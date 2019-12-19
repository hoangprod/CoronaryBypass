#pragma once


//structures
typedef struct _SSDTStruct
{
    LONG* pServiceTable;
    PVOID pCounterTable;
#ifdef _WIN64
    ULONGLONG NumberOfServices;
#else
    ULONG NumberOfServices;
#endif
    PCHAR pArgumentTable;
} SSDTStruct, * PSSDTStruct;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
    SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


SSDTStruct* SSDTfind();
PVOID GetFunctionAddress(const char* apiname);