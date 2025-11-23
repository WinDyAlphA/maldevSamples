#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

BOOL GetProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = 0,
		dwReturnLen2 = 0,
		dwNmbrOfPids = 0;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// Get the array of PIDs
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is not NULL
		if (adwProcesses[i] != 0) {

			// Open a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// If EnumProcessModules succeeded
					// Get the name of 'hProcess' and save it in the 'szProc' variable 
					if (!GetModuleBaseNameW(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
                        //wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProc, adwProcesses[i]);
						if (wcscmp(szProcName, szProc) == 0) {
							wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							// Return by reference
							*pdwPid		= adwProcesses[i];
							*phProcess	= hProcess;
							break;	
						}
                    }
				}

				// Close process handle 
				CloseHandle(hProcess);
			}
		}

		// Iterate through the PIDs array  
	}

	return TRUE;
}

int main(){
    DWORD pid = 0;
    HANDLE phProcess = NULL;
    GetProcessHandle(L"Notepad.exe",&pid,&phProcess);

    return 0;
}