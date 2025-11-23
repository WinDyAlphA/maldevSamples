#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <wchar.h>

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

    if (!szProcessName || !dwProcessId || !hProcess)
        return FALSE;

    *dwProcessId = 0;
    *hProcess    = NULL;

    PROCESSENTRY32W Proc;
    Proc.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE){
        printf("[!] CreateToolhelp32Snapshot Failed With Error : %lu \n", GetLastError());
        goto _EndOfFunction;
    }

    if (!Process32FirstW(hSnapShot, &Proc)) {
        printf("[!] Process32FirstW Failed With Error : %lu \n", GetLastError());
        goto _EndOfFunction;
    }

    do {
        if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
            *dwProcessId = Proc.th32ProcessID;
            *hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId);
            if (*hProcess == NULL)
                printf("[!] OpenProcess Failed With Error : %lu \n", GetLastError());
            break;
        }
    } while (Process32NextW(hSnapShot, &Proc));

_EndOfFunction:
    if (hSnapShot && hSnapShot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapShot);

    return (*dwProcessId != 0 && *hProcess != NULL);
}

int main(void) {
    HANDLE	hProcess		= NULL;
	DWORD	dwProcessId		= 0;
    LPCWSTR processName     = L"Notepad.exe";

    wprintf(L"[i] Searching For Process Id Of \"%s\" ... \n", processName);
	if (!GetRemoteProcessHandle(processName, &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	wprintf(L"[+] DONE \n");
	
	

	printf("[i] Found Target Process Pid: %d \n", dwProcessId);

    return 0;
}
