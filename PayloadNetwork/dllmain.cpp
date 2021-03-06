// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include <winsock2.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

BYTE hook[6];
BYTE hook2[6];
BYTE jmp[6] = { 0xe9,0x00, 0x00, 0x00, 0x00 ,0xc3 };
ofstream myfile;
ofstream myfile2;
DWORD pPrevious;

DWORD WINAPI CreateMessageBox(LPCSTR lpParam) {
	MessageBox(NULL, lpParam, "Dll says:", MB_OK);
	return 0;
}

DWORD HookFunction(LPCSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0);
	DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);
	VirtualProtect((void*)dwAddr, 6, PAGE_EXECUTE_READWRITE, &pPrevious);
	memcpy(&jmp[1], &dwCalc, 4);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
	VirtualProtect((void*)dwAddr, 6, pPrevious, &pPrevious);
	FlushInstructionCache(GetCurrentProcess(), 0, 0);
	return dwAddr;
}

BOOL UnHookFunction(LPCSTR lpModule, LPCSTR lpFuncName, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);

	if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0))
		return TRUE;
	FlushInstructionCache(GetCurrentProcess(), 0, 0);

	return FALSE;
}

int __stdcall nSend(SOCKET s, const char *buf, int len, int flags) {
	UnHookFunction("ws2_32.dll", "WSASend", hook);

	int result = send(s, buf, len, flags);

	myfile.open("C:\\tmp\\log.txt", ios::app | ios::binary);
	myfile << buf;
	myfile.close();

	HookFunction("ws2_32.dll", "WSASend", (LPVOID*)nSend, hook);
	return result;
}

int __stdcall nRecv(SOCKET s, char* buf, int len, int flags)
{
	UnHookFunction("ws2_32.dll", "WSARecv", hook2);
	DWORD tmp;

	len = recv(s, buf, len, flags);

	if (len > 0)
	{

		myfile2.open("C:\\tmp\\log.txt", ios::app | ios::binary);
		myfile2 << buf;
		myfile2.close();
	}
	HookFunction("ws2_32.dll", "WSARecv", (LPVOID*)nRecv, hook2);
	return len;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateMessageBox("You Been Injected!");
		HookFunction("ws2_32.dll", "WSASend", (LPVOID*)nSend, hook);
		HookFunction("ws2_32.dll", "WSARecv", (LPVOID*)nRecv, hook2);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

