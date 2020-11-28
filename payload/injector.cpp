#include "stdafx.h"

#include "Injector.h"
DWORD WINAPI CreateMessageBox(LPCWSTR lpParam) {
	MessageBox(NULL, lpParam, L"Dll says:", MB_OK);
	return 0;
}

DllExport void injectString(LPCWSTR param1)
{
	CreateMessageBox(param1);
}