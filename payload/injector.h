#pragma once
#include "stdafx.h"

#define DllExport extern "C" __declspec( dllexport )

DllExport void injectString(LPCWSTR param1);

DWORD WINAPI CreateMessageBox(LPCWSTR lpParam);