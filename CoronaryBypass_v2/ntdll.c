#include "Global.h"
#include "ntdll.h"
#include "Helpers.h"

unsigned char* FileData = 0;
ULONG FileSize = 0;

ULONG RvaToSection(IMAGE_NT_HEADERS* pNtHdr, ULONG dwRVA)
{
    USHORT wSections;
    PIMAGE_SECTION_HEADER pSectionHdr;
    pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
    wSections = pNtHdr->FileHeader.NumberOfSections;
    for (int i = 0; i < wSections; i++)
    {
        if (pSectionHdr[i].VirtualAddress <= dwRVA)
            if ((pSectionHdr[i].VirtualAddress + pSectionHdr[i].Misc.VirtualSize) > dwRVA)
            {
                return i;
            }
    }
    return (ULONG)-1;
}

ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG szFileSize)
{
    PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
    USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
    for (int i = 0; i < NumberOfSections; i++)
    {
        if (psh->VirtualAddress <= Rva)
        {
            if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
            {
                Rva -= psh->VirtualAddress;
                Rva += psh->PointerToRawData;
                return Rva < szFileSize ? Rva : PE_ERROR_VALUE;
            }
        }
        psh++;
    }
    return PE_ERROR_VALUE;
}

ULONG GetExportOffset(const unsigned char* FileDataH, ULONG szFileSize, const char* ExportName)
{
    //Verify DOS Header
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileDataH;
    if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DbgPrint("[69] Invalid IMAGE_DOS_SIGNATURE!\r\n");
        return PE_ERROR_VALUE;
    }

    //Verify PE Header
    PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileDataH + pdh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE)
    {
        DbgPrint("[69] Invalid IMAGE_NT_SIGNATURE!\r\n");
        return PE_ERROR_VALUE;
    }

    //Verify Export Directory
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory;
    else
        pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory;
    ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    ULONG ExportDirOffset = RvaToOffset(pnth, ExportDirRva, szFileSize);
    if (ExportDirOffset == PE_ERROR_VALUE)
    {
        DbgPrint("[69] Invalid Export Directory!\r\n");
        return PE_ERROR_VALUE;
    }

    //Read Export Directory
    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileDataH + ExportDirOffset);
    ULONG NumberOfNames = ExportDir->NumberOfNames;
    ULONG AddressOfFunctionsOffset = RvaToOffset(pnth, ExportDir->AddressOfFunctions, szFileSize);
    ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pnth, ExportDir->AddressOfNameOrdinals, szFileSize);
    ULONG AddressOfNamesOffset = RvaToOffset(pnth, ExportDir->AddressOfNames, szFileSize);
    if (AddressOfFunctionsOffset == PE_ERROR_VALUE ||
        AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
        AddressOfNamesOffset == PE_ERROR_VALUE)
    {
        DbgPrint("[69] Invalid Export Directory Contents!\r\n");
        return PE_ERROR_VALUE;
    }
    ULONG* AddressOfFunctions = (ULONG*)(FileDataH + AddressOfFunctionsOffset);
    USHORT* AddressOfNameOrdinals = (USHORT*)(FileDataH + AddressOfNameOrdinalsOffset);
    ULONG* AddressOfNames = (ULONG*)(FileDataH + AddressOfNamesOffset);

    //Find Export
    ULONG ExportOffset = PE_ERROR_VALUE;
    for (ULONG i = 0; i < NumberOfNames; i++)
    {
        ULONG CurrentNameOffset = RvaToOffset(pnth, AddressOfNames[i], szFileSize);
        if (CurrentNameOffset == PE_ERROR_VALUE)
            continue;
        const char* CurrentName = (const char*)(FileDataH + CurrentNameOffset);
        ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
        if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
            continue; //we ignore forwarded exports
        if (!strcmp(CurrentName, ExportName))  //compare the export name to the requested export
        {
            ExportOffset = RvaToOffset(pnth, CurrentFunctionRva, szFileSize);
            break;
        }
    }

    if (ExportOffset == PE_ERROR_VALUE)
    {
        DbgPrint("[69] Export %s not found in export table!\r\n", ExportName);
    }

    return ExportOffset;
}

PVOID GetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr)
{
    if ((unsigned char*)ptr < (unsigned char*)lpHeader)
        return 0;
    ULONG dwRva = (ULONG)((unsigned char*)ptr - (unsigned char*)lpHeader);
    IMAGE_DOS_HEADER* pdh = (IMAGE_DOS_HEADER*)lpHeader;
    if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*)((unsigned char*)lpHeader + pdh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    IMAGE_SECTION_HEADER* psh = IMAGE_FIRST_SECTION(pnth);
    int section = RvaToSection(pnth, dwRva);
    if (section == -1)
        return 0;
    if (Size)
        *Size = psh[section].SizeOfRawData;
    return (PVOID)((unsigned char*)lpHeader + psh[section].VirtualAddress);
}


NTSTATUS Initialize()
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
    InitializeObjectAttributes(&ObjectAttributes, &FileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
#ifdef _DEBUG
        DbgPrint("[69] KeGetCurrentIrql != PASSIVE_LEVEL!\n");
#endif
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (NT_SUCCESS(NtStatus))
    {
        FILE_STANDARD_INFORMATION StandardInformation = { 0 };
        NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if (NT_SUCCESS(NtStatus))
        {
            FileSize = StandardInformation.EndOfFile.LowPart;
            DbgPrint("[69] FileSize of ntdll.dll is %08X!\r\n", StandardInformation.EndOfFile.LowPart);
            FileData = (unsigned char*)RtlAllocateMemory(true, FileSize);

            LARGE_INTEGER ByteOffset;
            ByteOffset.LowPart = ByteOffset.HighPart = 0;
            NtStatus = ZwReadFile(FileHandle,
                NULL, NULL, NULL,
                &IoStatusBlock,
                FileData,
                FileSize,
                &ByteOffset, NULL);

            if (!NT_SUCCESS(NtStatus))
            {
                RtlFreeMemory(FileData);
                DbgPrint("[69] ZwReadFile failed with status %08X...\r\n", NtStatus);
            }
        }
        else
            DbgPrint("[69] ZwQueryInformationFile failed with status %08X...\r\n", NtStatus);
        ZwClose(FileHandle);
    }
    else
        DbgPrint("[69] ZwCreateFile failed with status %08X...\r\n", NtStatus);
    return NtStatus;
}

VOID Deinitialize()
{
    RtlFreeMemory(FileData);
}

INT GetExportSsdtIndex(const char* ExportName)
{
    ULONG_PTR ExportOffset = GetExportOffset(FileData, FileSize, ExportName);
    if (ExportOffset == PE_ERROR_VALUE)
        return -1;

    int SsdtOffset = -1;
    unsigned char* ExportData = FileData + ExportOffset;
    for (int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
    {
        if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
            break;
        if (ExportData[i] == 0xB8)  //mov eax,X
        {
            SsdtOffset = *(int*)(ExportData + i + 1);
            break;
        }
    }

    if (SsdtOffset == -1)
    {
        DbgPrint("[69] SSDT Offset for %s not found...\r\n", ExportName);
    }

    return SsdtOffset;
}