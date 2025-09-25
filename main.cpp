#include "structs.h"
#include <stdio.h>

CONST CHAR* dlls[] = {
    "advapi32.dll",
    "dbghelp.dll",
    "psapi.dll",
    "tlhelp32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "winhttp.dll",
    "urlmon.dll",
    "iphlpapi.dll",
    "netapi32.dll",
    "srvcli.dll",
    "mpr.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "cryptsvc.dll",
    "ole32.dll",
    "oleaut32.dll",
    "comdlg32.dll",
    "mscoree.dll",
    "msxml3.dll",
    "msxml6.dll",
    "vbscript.dll",
    "jscript.dll",
    "user32.dll",
    "gdi32.dll",
    "imm32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "shcore.dll",
    "comctl32.dll",
    "rpcrt4.dll",
    "wevtapi.dll",
    "winevt.dll",
    "sechost.dll",
    "setupapi.dll",
    "cfgmgr32.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
    "msvcp140.dll",
    "taskschd.dll",
    "schannel.dll",
    "ntshrui.dll",
    "wsock32.dll"

};

BOOL GetExportDirectory(PBYTE ImageBase, PIMAGE_EXPORT_DIRECTORY* ExportTable)
{
    if (!ImageBase || !ExportTable)
        return FALSE;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;
    *ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    return TRUE;
}

BOOL IsFuncBeingHooked(PVOID pFuncAddr, PVOID moduleBase, DWORD moduleSize)
{

    ULONG_PTR funcAddr = (ULONG_PTR)pFuncAddr;
    ULONG_PTR modBase = (ULONG_PTR)moduleBase;
    ULONG_PTR modEnd = modBase + moduleSize;

    BYTE firstByte = *(PBYTE)pFuncAddr;

    if (firstByte == 0xE9) {
        LONG offset = *(PDWORD)((PBYTE)pFuncAddr + 1);
        ULONG_PTR jumpTarget = funcAddr + 5 + offset;
        if (jumpTarget < modBase || jumpTarget >= modEnd) {
            // printf("Function at %p is hooked with a JMP to %p\n", pFuncAddr, (PVOID)jumpTarget);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL CheckHook()
{

    PPEB peb = (PPEB)__readgsqword(0x60); 
    if (!peb || !peb->Ldr)
        return FALSE;
    WCHAR* dllName = NULL;
    PVOID pBaseAddr = NULL;
    DWORD count = 0;
    PLDR_DATA_TABLE_ENTRY pDLL = (PLDR_DATA_TABLE_ENTRY)((PBYTE)peb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    for (int i = 0; i < sizeof(dlls) / sizeof(dlls[0]); i++) {
        LoadLibraryA(dlls[i]);
    }
    printf("-------------\n");
    while (pDLL->BaseDllName.Buffer) {
        dllName = pDLL->BaseDllName.Buffer;
        pBaseAddr = pDLL->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pBaseAddr;
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }
        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pBaseAddr + DosHeader->e_lfanew);
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }
        DWORD moduleSize = NtHeaders->OptionalHeader.SizeOfImage;

        PIMAGE_EXPORT_DIRECTORY ExportTable = nullptr;
        if (!GetExportDirectory((PBYTE)pBaseAddr, &ExportTable)) {
            continue;
        }
        PDWORD AddressOfFunctions = (PDWORD)((PBYTE)pBaseAddr + ExportTable->AddressOfFunctions);
        PDWORD AddressOfNames = (PDWORD)((PBYTE)pBaseAddr + ExportTable->AddressOfNames);
        PWORD AddressOfNameOrdinals = (PWORD)((PBYTE)pBaseAddr + ExportTable->AddressOfNameOrdinals);

        printf("Checking hooks in %S...,module base: %p,module size: %d\n", dllName, pBaseAddr, moduleSize);

        for (DWORD j = 0; j < ExportTable->NumberOfNames; j++) {
            PCHAR functionName = (PCHAR)((PBYTE)pBaseAddr + AddressOfNames[j]);
            DWORD FunctionAddress = AddressOfFunctions[AddressOfNameOrdinals[j]];
            PVOID funcAddress = (PBYTE)pBaseAddr + FunctionAddress;
            if (IsFuncBeingHooked(funcAddress, pBaseAddr, moduleSize)) {
                count++;
                wprintf(L"%-15s%-40S is hooked!, hook addr: %p\n", dllName, functionName, funcAddress);
                // printf("%-15S%-40s\n", dllName, functionName);
            }
        }

        pDLL = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pDLL->InMemoryOrderLinks.Flink - 0x10);
    }
    printf("Total hooked functions found: %d\n", count);
    return TRUE;
}

int main()
{
    CheckHook();
    system("pause");
    return 0;
}
