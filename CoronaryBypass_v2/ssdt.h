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

#pragma pack(push,1)
typedef struct _HOOKOPCODES
{
#ifdef _WIN64
    unsigned short int mov;
#else
    unsigned char mov;
#endif
    ULONG_PTR addr;
    unsigned char push;
    unsigned char ret;
} HOOKOPCODES;
#pragma pack(pop)

typedef struct _HOOKSTRUCT
{
    ULONG_PTR addr;
    HOOKOPCODES hook;
    unsigned char orig[sizeof(HOOKOPCODES)];
    LONG SSDTnew;
    ULONG_PTR SSDTaddress;
}HOOKSTRUCT, *HOOK;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
    SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


SSDTStruct* SSDTfind();
PVOID GetFunctionAddress(const char* apiname);