#include"stllist.h"
void the_username_sid(list <info>&gqlist)
{
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		if (!it->path)
		{
			it->SID = NULL;
			memset(it->ownerName, 0, 256);
			memcpy(it->ownerName,"NoOwner",strlen("NoOwner"));
			continue;
		}
		PSID ownerSid;
		PSID pSid;
		PACL dacl;
		PACL sacl;
		PSECURITY_DESCRIPTOR sd;
		DWORD result = GetNamedSecurityInfoA(it->path, SE_FILE_OBJECT, GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION ,
			&ownerSid, NULL, &dacl,&sacl, &sd);// путь файл владелец объекта и первичная инфа сид владельца сидгурппы(нулл),
		//получение SID по имени объекта(в этом случае - файл)

		SID_NAME_USE type;
		DWORD strsize = MAX_PATH;
		//char ownerName[MAX_PATH];
		char ownerDomain[MAX_PATH];
		if (LookupAccountSidA(NULL, ownerSid, it->ownerName, &strsize, ownerDomain, &strsize, &type))// определяем имя учетки по SID
		{
			char *sidDisplay;
			
	//			memset(it->SID, 0, 256);
			ConvertSidToStringSidA(ownerSid,&sidDisplay);
			it->SID = sidDisplay;
			//printf("    Owner   %20s | SID: %50s\n", it->ownerName, it->SID);
			//printf("    Owner   %20s | SID: %50s\n", it->ownerName, it->SID);
		}
		else
		{
			it->SID = NULL;
			memset(it->ownerName, 0, 256);
			memcpy(it->ownerName, "NoOwner", strlen("NoOwner"));
		}
	}
}












/*#include <comdef.h>
#define MAX_NAME 256
BOOL GetLogonFromToken(HANDLE hToken)
{
	DWORD dwSize = MAX_NAME;
	BOOL bSuccess = FALSE;
	DWORD dwLength = 0;
	PTOKEN_USER ptu = NULL;
	//Verify the parameter passed in is not NULL.
	if (NULL == hToken)
		goto Cleanup;

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		0,              // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto Cleanup;

		ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwLength);

		if (ptu == NULL)
			goto Cleanup;
	}

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		goto Cleanup;
	}
	SID_NAME_USE SidType;
	char lpName[MAX_NAME];
	char lpDomain[MAX_NAME];

	if (!LookupAccountSid(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
	{
		DWORD dwResult = GetLastError();
		if (dwResult == ERROR_NONE_MAPPED)
			strcpy_s(lpName, "NONE_MAPPED");
		else
		{
			printf("LookupAccountSid Error %u\n", GetLastError());
		}
	}
	else
	{
		printf("Current user is  %s\\%s\n",
			lpDomain, lpName);
		bSuccess = TRUE;
	}

Cleanup:

	if (ptu != NULL)
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
	return bSuccess;
}

HRESULT GetUserFromProcess(const DWORD procId)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
	if (hProcess == NULL)
		return E_FAIL;
	HANDLE hToken = NULL;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProcess);
		return E_FAIL;
	}
	BOOL bres = GetLogonFromToken(hToken);

	CloseHandle(hToken);
	CloseHandle(hProcess);
	return bres ? S_OK : E_FAIL;
}*/