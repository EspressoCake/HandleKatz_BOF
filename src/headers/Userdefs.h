#pragma once

#include <windows.h>
#include <stdio.h>
#include "beacon.h"


// Definitions
#define BASE64_DECODE_INVALID       0x300
#define BASE64_DECODE_PADDING       0x100
#define BASE64_DECODE_WHITESPACE    0x200


// Forward declarations
size_t  internalStrlenA (const char* str);
int     internalCompare (const char* X, const char* Y);
const   char*   internalStrStr (const char* X, const char* Y);
static  int     internalAtoi (const char* str);
BOOL    WINAPI  internalCryptStringToBinaryA (LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags );
static  LONG    internalBase64ToBinaryA	( LPCSTR pszString, DWORD cchString, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);
static  LONG    internalBase64ToBinary ( const void* pszString, BOOL wide, DWORD cchString, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags );
static  int     internalDecodeBase64Byte (int c);


// Implementations
size_t internalStrlenA(const char* str)
{
    const char* s;

    for (s = str; *s; ++s)
    {
        ;
    }

    return (s - str);
}


static int internalAtoi (const char* str)
{
    int result = 0;

    for ( int i = 0; str[i] != '\0'; ++i )
    {
        result = result * 10 + str[i] - '0';
    }

    return result;
}


// returns true if `X` and `Y` are the same
int internalCompare(const char *X, const char *Y)
{
    while (*X && *Y)
    {
        if (*X != *Y) {
            return 0;
        }
 
        X++;
        Y++;
    }
 
    return (*Y == '\0');
}


const char* internalStrStr(const char* X, const char* Y)
{
    while (*X != '\0')
    {
        if ((*X == *Y) && internalCompare(X, Y)) {
            return X;
        }
        X++;
    }
 
    return NULL;
}


static LONG internalBase64ToBinaryA(LPCSTR pszString, DWORD cchString, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags)
{
    return internalBase64ToBinary(pszString, FALSE, cchString, pbBinary, pcbBinary, pdwSkip, pdwFlags);
}


static int internalDecodeBase64Byte(int c)
{
    int ret = BASE64_DECODE_INVALID;
 
    if (c >= 'A' && c <= 'Z')
        ret = c - 'A';
    else if (c >= 'a' && c <= 'z')
        ret = c - 'a' + 26;
    else if (c >= '0' && c <= '9')
        ret = c - '0' + 52;
    else if (c == '+')
        ret = 62;
    else if (c == '/')
        ret = 63;
    else if (c == '=')
        ret = BASE64_DECODE_PADDING;
    else if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        ret = BASE64_DECODE_WHITESPACE;
    return ret;
}


static  LONG internalBase64ToBinary(const void* pszString, BOOL wide, DWORD cchString, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags)
{
    DWORD cbIn, cbValid, cbOut, hasPadding;
    BYTE block[4];
    for (cbIn = cbValid = cbOut = hasPadding = 0; cbIn < cchString; ++cbIn)
    {
        int c = wide ? (int)((WCHAR*)pszString)[cbIn] : (int)((char*)pszString)[cbIn];
        int d = internalDecodeBase64Byte(c);
        if (d == BASE64_DECODE_INVALID)
           goto invalid;
        if (d == BASE64_DECODE_WHITESPACE)
           continue;
 
        /* When padding starts, data is not acceptable */
        if (hasPadding && d != BASE64_DECODE_PADDING)
           goto invalid;
 
        /* Padding after a full block (like "VVVV=") is ok and stops decoding */
        if (d == BASE64_DECODE_PADDING && (cbValid & 3) == 0)
           break;
 
        cbValid += 1;
 
        if (d == BASE64_DECODE_PADDING)
        {
           hasPadding = 1;
           /* When padding reaches a full block, stop decoding */
           if ((cbValid & 3) == 0)
              break;
           continue;
        }
 
        /* cbOut is incremented in the 4-char block as follows: "1-23" */
        if ((cbValid & 3) != 2)
           cbOut += 1;
    }
    /* Fail if the block has bad padding; omitting padding is fine */
    if ((cbValid & 3) != 0 && hasPadding)
        goto invalid;
    /* Check available buffer size */
    if (pbBinary && *pcbBinary && cbOut > *pcbBinary)
        goto overflow;
    /* Convert the data; this step depends on the validity checks above! */
    if (pbBinary) for (cbIn = cbValid = cbOut = 0; cbIn < cchString; ++cbIn)
    {
        int c = wide ? (int)((WCHAR*)pszString)[cbIn] : (int)((char*)pszString)[cbIn];
        int d = internalDecodeBase64Byte(c);
        if (d == BASE64_DECODE_WHITESPACE)
           continue;
        if (d == BASE64_DECODE_PADDING)
           break;
        block[cbValid & 3] = d;
        cbValid += 1;
        switch (cbValid & 3) {
        case 1:
           pbBinary[cbOut++] = (block[0] << 2);
           break;
        case 2:
           pbBinary[cbOut-1] = (block[0] << 2) | (block[1] >> 4);
           break;
        case 3:
           pbBinary[cbOut++] = (block[1] << 4) | (block[2] >> 2);
           break;
        case 0:
           pbBinary[cbOut++] = (block[2] << 6) | (block[3] >> 0);
           break;
        }
    }
    *pcbBinary = cbOut;
    if (pdwSkip)
        *pdwSkip = 0;
    if (pdwFlags)
        *pdwFlags = CRYPT_STRING_BASE64;
    return ERROR_SUCCESS;
 
 overflow:
    return ERROR_INSUFFICIENT_BUFFER;
 invalid:
    *pcbBinary = cbOut;
    return ERROR_INVALID_DATA;
 }


BOOL WINAPI internalCryptStringToBinaryA (LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags )
{
    if ( dwFlags == CRYPT_STRING_BASE64 )
    {
        if ( !cchString )
        {
            cchString = internalStrlenA(pszString);
        }

        int returnValue = internalBase64ToBinaryA(pszString, cchString, pbBinary, pcbBinary, pdwSkip, pdwFlags);

        if (returnValue)
        {
            return returnValue;
        } else {
            return returnValue == ERROR_SUCCESS;
        }
    } else {
        return FALSE;
    }
}