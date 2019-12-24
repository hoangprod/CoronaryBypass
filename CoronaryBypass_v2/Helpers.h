#pragma once

typedef struct _MEMORY_OFFSETS {
	LONG off0;
	LONG off1;
	LONG off2;
	LONG off3;
	LONG off4;
	LONG off5;
	LONG off6;
	LONG off7;
	LONG off8;
	LONG off9;
} MEMORY_OFFSETS, * PMEMORY_OFFSETS;

typedef struct _MEMORY_PATTERN_SCAN {
	OS_INDEX OsIndex;
	PUCHAR pattern;
	PWCHAR start;
	PWCHAR end;
	MEMORY_OFFSETS Offsets;
} MEMORY_PATTERN_SCAN, * PMEMORY_PATTERN_SCAN;

typedef struct _ACE_ARRAY {
	ACE_HEADER Header;
	ACCESS_MASK Mask;
	ULONG SidStart;
} ACE_ARRAY, * PACE_ARRAY;

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize);
void RtlFreeMemory(void* InPointer);
NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length);

bool isPrivilegeProcess(HANDLE pid);

bool isWriteableObject(PISECURITY_DESCRIPTOR SecurityDescriptor);

OS_INDEX getWindowsIndex();

ULONG getWindowsBuildNumber();

VOID InterlockedSet(LONG* Destination, LONG Source);

BOOLEAN compareMaskPattern(PUCHAR szSource, PCUCHAR szPattern, PCUCHAR szMask);

NTSTATUS get_os_pattern(MEMORY_PATTERN_SCAN* pattern, MEMORY_PATTERN_SCAN patterns[], INT arrLength);

ULONG64 pattern_scan(ULONG64 pData, ULONG64 RegionSize, PCUCHAR szPattern, PCUCHAR szMask, INT Len, INT Offset);