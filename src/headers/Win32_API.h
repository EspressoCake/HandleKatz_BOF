#pragma once

#include <windows.h>

WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);