#include"stllist.h"
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)
void showlist(list <info> g)
{
	list <info> ::iterator it;
	for (it = g.begin(); it != g.end(); ++it)
	{
		cout <<"ProcessID "<<it->num_PID << " ImageFileName "<<it->name_PID<<'\n';
	}
}
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;// 2 byte char
} UNICODE_STRING;

typedef LONG KPRIORITY; // Thread priority

typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads; //no need(at night 17.09)
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef NTSTATUS(WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,IN OUT PVOID SystemInformation,IN ULONG SystemInformationLength,OUT OPTIONAL  PULONG ReturnLength);
void get_first_three(list <info> &gqlist)
{
	size_t bufferSize = 102400;
	PSYSTEM_PROCESS_INFORMATION_DETAILD pspid =
		(PSYSTEM_PROCESS_INFORMATION_DETAILD)malloc(bufferSize);
	ULONG ReturnLength;
	PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
	NTSTATUS status;

	while (TRUE) {
		status = pfnNtQuerySystemInformation(SystemProcessInformation, (PVOID)pspid,
			bufferSize, &ReturnLength);
		if (status == STATUS_SUCCESS)
			break;
		else if (status != STATUS_INFO_LENGTH_MISMATCH) { // 0xC0000004L
		
		}

		bufferSize *= 2;
		pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)realloc((PVOID)pspid, bufferSize);
	}

	for (;;
		pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)(pspid->NextEntryOffset + (PBYTE)pspid)) {

		//_tprintf(TEXT("ProcessId: %d, ImageFileName: %ls\n"), pspid->UniqueProcessId,
		//	(pspid->ImageName.Length && pspid->ImageName.Buffer) ? pspid->ImageName.Buffer : L"");
		info name;
		name.num_PID = unsigned(pspid->UniqueProcessId);
		wchar_t buf[100];
		wmemset(buf, 0, 100);
		//int k = wcslen((pspid->ImageName.Length && pspid->ImageName.Buffer) ? pspid->ImageName.Buffer : L"");
		//name.name_PID = new wchar_t [k+1];
		wmemcpy(buf, (pspid->ImageName.Length && pspid->ImageName.Buffer) ? pspid->ImageName.Buffer : L"", 100);
		if (!wcscmp(buf, L"")) // don't copy proccesses without names!!
		{
			continue;
		}
		wcsncpy_s(name.name_PID, buf, 100);
		//name.name_PID = (pspid->ImageName.Length && pspid->ImageName.Buffer) ? pspid->ImageName.Buffer : L"";
		gqlist.push_back(name);
		if (pspid->NextEntryOffset == 0) break;
	}
	//showlist(gqlist);
	exe_path(gqlist);
}

void exe_path(list <info> &gqlist)
{
	//DWORD PID = 1337; // something here
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, it->num_PID);// не наследуется
		if (hProcess == NULL)
		{
			it->path = NULL;
			continue;
		}
		DWORD value = MAX_PATH;
		char buffer[MAX_PATH]="\0";
		//if (it->num_PID == 0 || strcmp(it->name_PID,L""))
		//	continue;
		QueryFullProcessImageName(hProcess, 0, buffer, &value);// 0 - name in win 32 path form, value - amount of letters полное имя полняемго процесса
		//int k=GetLastError();
		//if (k == 6)
		//	continue;
		//printf("EXE Path: %s\n", buffer);
		it->path = new char[strlen(buffer)+1];
		memset(it->path, 0, strlen(buffer) + 1);
		memcpy(it->path, buffer, strlen(buffer)*sizeof(char));
	}
}
