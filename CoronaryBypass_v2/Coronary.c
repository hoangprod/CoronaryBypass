#include "Global.h"
#include "Coronary.h"

//
// Check if a local file or dir exists (via open)
//
BOOLEAN CheckElementExistsViaOpen(PUNICODE_STRING puPath)
{
	IO_STATUS_BLOCK IoStatus;

	NTSTATUS status = GetExistenceStatus(puPath, &IoStatus);

	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	else if ((status == STATUS_OBJECT_NAME_NOT_FOUND) ||
		(IoStatus.Information == FILE_DOES_NOT_EXIST) ||
		(status == STATUS_OBJECT_PATH_NOT_FOUND) ||
		(status == STATUS_OBJECT_NAME_INVALID) ||
		(status == STATUS_OBJECT_PATH_INVALID))
	{
		return FALSE;
	}

	return TRUE;
}

//
// Get element's existence status
//
NTSTATUS GetExistenceStatus(PUNICODE_STRING puPath, PIO_STATUS_BLOCK pIoStatus)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES aFileAttrib;
	FILE_NETWORK_OPEN_INFORMATION aInfo;

#if (WINVER>=0x500)

	InitializeObjectAttributes(&aFileAttrib, puPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

#else

	InitializeObjectAttributes(&aFileAttrib, puPath,
		OBJ_CASE_INSENSITIVE, NULL, NULL);

#endif

	//
	// Use FastOpen (if possible). If not that call will roll
	// create IRP.
	//

	// Fast Pseudo-open file to get status
	status = IoFastQueryNetworkAttributes(&aFileAttrib, SYNCHRONIZE, 0,
		pIoStatus, &aInfo);

	if (NT_SUCCESS(status))
	{
		status = pIoStatus->Status;
	}

	return status;
}

//
// IOTCL to print a user supplied message.
//
NTSTATUS PrintMsg(PSPECIAL_BUFFER data)
{
	DbgPrint("[69] %S of size %d.\n", *(PWSTR*)(data->inBuffer), *(data->szBufferIn));
	
	UNICODE_STRING Text2 = RTL_CONSTANT_STRING(L"Hello World from Kernel");

	DbgPrint("[69] %S === size %d out of %d\n", Text2.Buffer, Text2.Length, Text2.MaximumLength);

	RtlStringCbCopyNW(data->outBuffer, *data->szBufferOut, Text2.Buffer, Text2.Length);

	return STATUS_SUCCESS;
}
