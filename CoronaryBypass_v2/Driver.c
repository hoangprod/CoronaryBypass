#include "Global.h"
#include "Coronary.h"
#include "Helpers.h"
#include "Callbacks.h"
#include "ntdll.h"
#include "ssdt.h"
#include "Hooks.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

DRIVER_DISPATCH CreateCall, CloseCall, UnSupported, SteakDispatchDeviceControl;

UNICODE_STRING DeviceName;
UNICODE_STRING DosDeviceName;


void DriverUnload(IN PDRIVER_OBJECT theDriverObject)
{
	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(theDriverObject->DeviceObject);

	Deinitialize();
	hookDeinitialize();
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);


	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS UnSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return STATUS_NOT_SUPPORTED;
}

NTSTATUS SteakDispatchDeviceControl(IN OUT DEVICE_OBJECT* DeviceObject, IN OUT IRP* Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS; // Use for later
	PIO_STACK_LOCATION irpStack = NULL;
	size_t szInBuffer, szOutBuffer, szReallyOut = 0;


	irpStack = IoGetCurrentIrpStackLocation(Irp);
	if (irpStack)
	{
		szInBuffer = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		szOutBuffer = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

		PVOID inBuffer = irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
		PVOID outBuffer = Irp->UserBuffer;

		SPECIAL_BUFFER ioBuffer = { &szInBuffer, &szOutBuffer, inBuffer, outBuffer };

		switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_APT69_BSOD:
			KeBugCheck(MANUALLY_INITIATED_CRASH);
			break;
		case IOCTL_APT69_PRINT:
			PrintMsg(&ioBuffer);
			break;
		case IOCTL_APT69_NOTIFY_PROCESS:
			break;
		}

		// Useless for now.
		if (NT_SUCCESS(status))
			szReallyOut = irpStack->Parameters.DeviceIoControl.OutputBufferLength - szOutBuffer;

		DbgPrint("[69] Information out is %d %d %d\n", szReallyOut, irpStack->Parameters.DeviceIoControl.OutputBufferLength, szOutBuffer);

	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 69;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	RtlInitUnicodeString(&DeviceName, L"\\Device\\CoronaryBypass");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\CoronaryBypass");

	UNREFERENCED_PARAMETER(theRegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject;
	ULONG i;

	if (getWindowsBuildNumber() >= WinVer_VISTA)
	{
		status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
		if (NT_SUCCESS(status))
		{

			for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
				pDriverObject->MajorFunction[i] = UnSupported;

			pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
			pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
			pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SteakDispatchDeviceControl;
			pDriverObject->DriverUnload = DriverUnload;

			pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
			IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

			if (!NT_SUCCESS(Initialize()))
			{
				DbgPrint("[69] Ntdll::Initialize() failed...\r\n");
				return STATUS_UNSUCCESSFUL;
			}

			PVOID NtCon = GetFunctionAddress("NtContinue");

			if (!NtCon)
				DbgPrint("[69] Failed to find NtContinue's Address.");
			else
				DbgPrint("[69] Found NtContinue at %p\n", NtCon);

			hookInitialize();

		}

	}
	else
	{
		status = STATUS_NOT_SUPPORTED;
	}

	return status;
}
