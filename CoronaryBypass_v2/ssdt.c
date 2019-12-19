#include "Global.h"
#include "ssdt.h"
#include "ntdll.h"

extern NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

// Thank you to mrexodia for the codes!!!

//Based on: http://alter.org.ua/docs/nt_kernel/procaddr
PVOID GetKernelBase(PULONG pImageSize)
{
    typedef struct _SYSTEM_MODULE_ENTRY
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[0];
    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

    PVOID pModuleBase = NULL;
    PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

    ULONG SystemInfoBufferSize = 0;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
        &SystemInfoBufferSize,
        0,
        &SystemInfoBufferSize);

    if (!SystemInfoBufferSize)
    {
        DbgPrint("[69] ZwQuerySystemInformation (1) failed...\r\n");
        return NULL;
    }

    pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, (SIZE_T)SystemInfoBufferSize * 2);

    if (!pSystemInfoBuffer)
    {
        DbgPrint("[69] ExAllocatePool failed...\r\n");
        return NULL;
    }

    memset(pSystemInfoBuffer, 0, (SIZE_T)SystemInfoBufferSize * 2);

    status = ZwQuerySystemInformation(SystemModuleInformation,
        pSystemInfoBuffer,
        SystemInfoBufferSize * 2,
        &SystemInfoBufferSize);

    if (NT_SUCCESS(status))
    {
        pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
        if (pImageSize)
            *pImageSize = pSystemInfoBuffer->Module[0].ImageSize;
    }
    else
        DbgPrint("[69] ZwQuerySystemInformation (2) failed...\r\n");

    ExFreePool(pSystemInfoBuffer);

    return pModuleBase;
}

//Based on: https://github.com/hfiref0x/WinObjEx64
SSDTStruct* SSDTfind()
{
    static SSDTStruct* SSDT = 0;
    if (!SSDT)
    {
#ifndef _WIN64
        //x86 code
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
        //x64 code
        ULONG kernelSize;
        ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase(&kernelSize);
        if (kernelBase == 0 || kernelSize == 0)
            return NULL;

        // Find KiSystemServiceStart
        const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
        const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
        bool found = false;
        ULONG KiSSSOffset;
        for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
        {
            if (RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
            {
                found = true;
                break;
            }
        }
        if (!found)
            return NULL;

        // lea r10, KeServiceDescriptorTable
        ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;
        LONG relativeOffset = 0;
        if ((*(unsigned char*)address == 0x4c) &&
            (*(unsigned char*)(address + 1) == 0x8d) &&
            (*(unsigned char*)(address + 2) == 0x15))
        {
            relativeOffset = *(LONG*)(address + 3);
        }
        if (relativeOffset == 0)
            return NULL;

        SSDT = (SSDTStruct*)(address + relativeOffset + 7);
#endif
    }

    DbgPrint("[69] SSDT Struct at %p\n", SSDT);

    return SSDT;
}


PVOID GetFunctionAddress(const char* apiname)
{
    //read address from SSDT
    SSDTStruct* SSDT = SSDTfind();
    if (!SSDT)
    {
        DbgPrint("[69] SSDT not found...\r\n");
        return 0;
    }
    ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
    if (!SSDTbase)
    {
        DbgPrint("[69] ServiceTable not found...\r\n");
        return 0;
    }
    ULONG readOffset = GetExportSsdtIndex(apiname);
    if (readOffset == -1)
        return 0;
    if (readOffset >= SSDT->NumberOfServices)
    {
        DbgPrint("[69] Invalid read offset...\r\n");
        return 0;
    }

    DbgPrint("[69] SSDT Index number for %s is %d\n", apiname, readOffset);

#ifdef _WIN64
    return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);
#else
    return (PVOID)SSDT->pServiceTable[readOffset];
#endif
}


void Unhook(HOOK hHook, bool free)
{
    if (!hHook)
        return;
    SSDTStruct* SSDT = SSDTfind();
    if (!SSDT)
    {
        DbgPrint("[TITANHIDE] SSDT not found...\r\n");
        return;
    }
    LONG* SSDT_Table = SSDT->pServiceTable;
    if (!SSDT_Table)
    {
        Log("[TITANHIDE] ServiceTable not found...\r\n");
        return;
    }
    InterlockedSet(&SSDT_Table[hHook->SSDTindex], hHook->SSDTold);
#ifdef _WIN64
    if (free)
        Unhook(hHook, true);
#else
    if (free)
        RtlFreeMemory(hHook);
#endif
}

HOOK hook_internal(ULONG_PTR addr, void* newfunc)
{
    //allocate structure
    HOOK hook = (HOOK)RtlAllocateMemory(true, sizeof(HOOKSTRUCT));
    //set hooking address
    hook->addr = addr;
    //set hooking opcode
#ifdef _WIN64
    hook->hook.mov = 0xB848;
#else
    hook->hook.mov = 0xB8;
#endif
    hook->hook.addr = (ULONG_PTR)newfunc;
    hook->hook.push = 0x50;
    hook->hook.ret = 0xc3;
    //set original data
    RtlCopyMemory(&hook->orig, (const void*)addr, sizeof(HOOKOPCODES));
    if (!NT_SUCCESS(RtlSuperCopyMemory((void*)addr, &hook->hook, sizeof(HOOKOPCODES))))
    {
        RtlFreeMemory(hook);
        return 0;
    }
    return hook;
}