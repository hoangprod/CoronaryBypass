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

OS_INDEX getWindowsIndex();

ULONG getWindowsBuildNumber();

BOOLEAN compareMaskPattern(PUCHAR szSource, PCUCHAR szPattern, PCUCHAR szMask);

NTSTATUS get_os_pattern(MEMORY_PATTERN_SCAN* pattern, MEMORY_PATTERN_SCAN patterns[], INT arrLength);

ULONG64 pattern_scan(ULONG64 pData, ULONG64 RegionSize, PCUCHAR szPattern, PCUCHAR szMask, INT Len, INT Offset);