#pragma once


#define PE_ERROR_VALUE (ULONG)-1

NTSTATUS Initialize();
VOID Deinitialize();
PVOID GetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr);
int GetExportSsdtIndex(const char* ExportName);
ULONG GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName);