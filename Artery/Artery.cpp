// Artery.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#define IOCTL_APT69_PRINT					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x001, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_APT69_BSOD					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x002, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_APT69_NOTIFY_PROCESS			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x003, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)


int Crash()
{
	HANDLE hDriver = CreateFileW(L"\\\\.\\CoronaryBypass", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	const WCHAR* StrInput = L"String received from userland.";

	WCHAR StrOut[100] = { 0 };
	DWORD ReturnBytes;
	

	if(hDriver && hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_APT69_PRINT, &StrInput, wcslen(StrInput) + 1, &StrOut, 100, &ReturnBytes, NULL);
		CloseHandle(hDriver); // !
		printf("Str: %S %d", StrOut, ReturnBytes);
	}
	else
	{
		printf("[!] Could not open handle to driver.\n");
	}

	return 0;
}

int main()
{
	Crash();
	std::cin.get();
}
