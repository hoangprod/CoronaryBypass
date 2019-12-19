#pragma once
#include <ntifs.h>
#include <fltkernel.h>
#include <ntddk.h>
#include <aux_klib.h>
#include <ntstrsafe.h>

typedef struct _SPECIAL_BUFFER {
	size_t* szBufferIn;
	size_t* szBufferOut;
	PVOID inBuffer;
	PVOID outBuffer;
} SPECIAL_BUFFER, * PSPECIAL_BUFFER;

typedef enum _OS_INDEX {
	WinVer_UNK = 0,
	WinVer_XP = 1,
	WinVer_2K3 = 2,
	WinVer_VISTA = 3,
	WinVer_7 = 4,
	WinVer_8 = 5,
	WinVer_BLUE = 6,
	WinVer_10_1507 = 7,
	WinVer_10_1511 = 8,
	WinVer_10_1607 = 9,
	WinVer_10_1703 = 10,
	WinVer_10_1709 = 11,
	WinVer_10_1803 = 12,
	WinVer_10_1809 = 13,
	WinVer_10_1903 = 14,
	WinVer_10_1909 = 15,
} OS_INDEX, * POS_INDEX;

#define IOCTL_APT69_PRINT					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x001, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_APT69_BSOD					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x002, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_APT69_NOTIFY_PROCESS			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x003, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma warning(disable:4204 4221 6340 6273 6328 28159)