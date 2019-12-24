#include "Global.h"
#include "Hooks.h"
#include "Helpers.h"
#include "ssdt.h"

typedef NTSTATUS(NTAPI* NTSETSECURITYOBJECT)(
	HANDLE               Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor
	);

typedef NTSTATUS(NTAPI* NTCREATEFILE)(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength
	);

static NTCREATEFILE NtCF = 0;

static NTSETSECURITYOBJECT NtSSO = 0;


NTSTATUS NTAPI oNtSetSecurityObject(
	HANDLE               Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor
)
{
	return NtSSO(Handle, SecurityInformation, SecurityDescriptor);
}

NTSTATUS NTAPI oNtCreateFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength)
{
	return NtCF(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


static HOOK hNtSetSecurityObject = 0;

static HOOK hNtCreateFile = 0;

static NTSTATUS NTAPI hook_NtSetSecurityObject(
	HANDLE               Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor
)
{

	// If Set DACL, Owner or Group
	if (SecurityInformation == DACL_SECURITY_INFORMATION || SecurityInformation == GROUP_SECURITY_INFORMATION || SecurityInformation == OWNER_SECURITY_INFORMATION)
	{

	}

	return oNtSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor);
}

static NTSTATUS NTAPI hook_NtCreateFile(
	OUT PHANDLE           FileHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN PLARGE_INTEGER     AllocationSize,
	IN ULONG              FileAttributes,
	IN ULONG              ShareAccess,
	IN ULONG              CreateDisposition,
	IN ULONG              CreateOptions,
	IN PVOID              EaBuffer,
	IN ULONG              EaLength)
{
	NTSTATUS rc;
	char ParentDirectory[1024];
	PUNICODE_STRING Parent = NULL;
	ParentDirectory[0] = '\0';

	if (ObjectAttributes->RootDirectory != 0) {
		PVOID Object;
		Parent = (PUNICODE_STRING)ParentDirectory;
		rc = ObReferenceObjectByHandle(ObjectAttributes->RootDirectory,
			0,
			0,
			KernelMode,
			&Object,
			NULL);

		if (rc == STATUS_SUCCESS) {
			ULONG BytesReturned;
			rc = ObQueryNameString(Object,(POBJECT_NAME_INFORMATION)ParentDirectory,sizeof(ParentDirectory),&BytesReturned);
			ObDereferenceObject(Object);
			if (rc != STATUS_SUCCESS)
				RtlInitUnicodeString(Parent,L"Unknown\\");
		}
		else
		{
			RtlInitUnicodeString(Parent,L"Unknown\\");
		}
	}
	HANDLE cPID = PsGetCurrentThreadId();
	
	rc = oNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	if (isWriteableObject(ObjectAttributes->SecurityDescriptor) )//&& isPrivilegeProcess(cPID))
	{
		DbgPrint("%d NtCreateFile : Filename = %S%S%S\n", cPID, Parent ? Parent->Buffer : L"", Parent ? L"\\" : L"", ObjectAttributes->ObjectName->Buffer);
	}
	return rc;
}

bool hookInitialize()
{
	if (!NtCF)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtCreateFile");
		NtCF = (NTCREATEFILE)MmGetSystemRoutineAddress(&routineName);
		if (!NtCF)
			return false;

		hNtCreateFile = Hook("NtCreateFile", (void*)hook_NtCreateFile);
	}

	if (!NtSSO)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtSetSecurityObject");
		NtSSO = (NTSETSECURITYOBJECT)MmGetSystemRoutineAddress(&routineName);
		if (!NtSSO)
			return false;

		hNtSetSecurityObject = Hook("NtSetSecurityObject", (void*)hook_NtSetSecurityObject);
	}

	return true;
}

void hookDeinitialize()
{
	Unhook(hNtCreateFile, true);
	Unhook(hNtSetSecurityObject, true);
}