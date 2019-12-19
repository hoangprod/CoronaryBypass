#include "Global.h"
#include "Helpers.h"


//
// Return Windows' build version number
//
ULONG getWindowsBuildNumber()
{
	NTSTATUS status = STATUS_SUCCESS;

	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

	if (NT_SUCCESS(status))
	{
		ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;

		DbgPrint(
			"[69] OS version %d.%d.%d.%d - 0x%x\n",
			verInfo.dwMajorVersion,
			verInfo.dwMinorVersion,
			verInfo.dwBuildNumber,
			verInfo.wServicePackMajor,
			ver_short
		);

		return verInfo.dwBuildNumber;
	}

	return 0;
}

//
// Return enum type for windows version
//
OS_INDEX getWindowsIndex()
{
	ULONG BuildNumber = getWindowsBuildNumber();

	switch (BuildNumber)
	{
	case 2600:
		return WinVer_XP;
		break;
	case 3790:
		return WinVer_2K3;
		break;
	case 6000:
	case 6001:
	case 6002:
		return WinVer_VISTA;
		break;
	case 7600:
	case 7601:
		return WinVer_7;
		break;
	case 8102:
	case 8250:
	case 9200:
		return WinVer_8;
	case 9431:
	case 9600:
		return WinVer_BLUE;
		break;
	case 10240:
		return WinVer_10_1507;
		break;
	case 10586:
		return WinVer_10_1511;
		break;
	case 14393:
		return WinVer_10_1607;
		break;
	case 15063:
		return WinVer_10_1703;
		break;
	case 16299:
		return WinVer_10_1709;
		break;
	case 17134:
		return WinVer_10_1803;
		break;
	case 17763:
		return WinVer_10_1809;
		break;
	case 18362:
		return WinVer_10_1903;
		break;
	case 18363:
		return WinVer_10_1909;
		break;
	default:
		return WinVer_UNK;
	}
}

//
// Compare byte and also check masking
//
BOOLEAN compareMaskPattern(PUCHAR szSource, PCUCHAR szPattern, PCUCHAR szMask)
{
	for (; *szMask; ++szSource, ++szPattern, ++szMask)
		if ((szMask && *szMask == 'x') || *szSource != *szPattern)
			return 0;
	return 1;
}

//
// Scan a region of memory for matching pattern
//
ULONG64 pattern_scan(ULONG64 pData, ULONG64 RegionSize, PCUCHAR szPattern, PCUCHAR szMask, INT Len, INT Offset)
{
	for (INT i = 0; i != RegionSize - Len; ++i, ++pData)
		if (compareMaskPattern((PUCHAR)pData, szPattern, szMask))
			return pData + Offset;
	return 0;
}

NTSTATUS get_os_pattern(MEMORY_PATTERN_SCAN * pattern, MEMORY_PATTERN_SCAN patterns[], INT arrLength)
{
	OS_INDEX curIndex = getWindowsIndex();

	if (curIndex)
	{
		for (int i = 0; i < arrLength; i++)
		{
			if (patterns[i].OsIndex == curIndex)
			{
				DbgPrint("[69] Found matching OSIndex of %d\n", curIndex);
				*pattern = patterns[i];
				return STATUS_SUCCESS;
			}
		}
	}
	else
	{
		ULONG buildNumber = getWindowsBuildNumber();
		DbgPrint("[69] Error: getWindowsIndex returned 0 / UNKNOWN version. (Windows Build Number: %ul)\n", buildNumber);
	}



	return STATUS_NOT_FOUND;
}