#include"stllist.h"
#include<WinError.h>

/*void setLevel()
{
	//добавить нахождение текущего intgrt levl 
	// и изменение
	WCHAR path[50]= L"C:\\Program Files\\Notepad++\\notepad++.exe";
	int lvl = 3;
	LPCWSTR INTEGRITY_SDDL_SACL_W = nullptr;
	if (lvl == 0)
		INTEGRITY_SDDL_SACL_W = L"";
	else if (lvl == 1)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;LW)";
	else if (lvl == 2)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;ME)";
	else if (lvl == 3)
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;HI)";

	DWORD dwErr = ERROR_SUCCESS;
	PSECURITY_DESCRIPTOR pSD = nullptr;
	PACL pSacl = nullptr;
	BOOL fSaclPresent = FALSE;
	BOOL fSaclDefaulted = FALSE;
	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, nullptr))
	{
		if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
		{
			dwErr = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, pSacl);
			if (dwErr == ERROR_SUCCESS)
			{
				LocalFree(pSD);
				return;
			}
		}
		LocalFree(pSD);
	}
	return;
}*/
void CreateFilesLowHighIntg(void)
{
	BOOL fRet;
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL TIL = { 0 };
	PROCESS_INFORMATION ProcInfo = { 0 };
	STARTUPINFO StartupInfo = { 0 };
	//WCHAR wszProcessName[MAX_PATH] = L"C:\\Program Files\\Notepad++\\notepad++.exe";
	WCHAR wszProcessName[MAX_PATH] = L"C:\\Users\\Elvin\\Documents\\testintgrty\\godhelpme.txt";
	//WCHAR wszIntegritySid[20] = L"S-1-16-4096"; //low
	
	//WCHAR wszIntegritySid[20] = L"S-1-16-8192";//medium 
	
	WCHAR wszIntegritySid[20] = L"S-1-16-12288"; //high


	
	//WCHAR wszIntegritySid[20] = L"S-1-16-0"; untrusted 
	//WCHAR wszIntegritySid[20] = L"S-1-16-4096"; low 
	//WCHAR wszIntegritySid[20] = L"S-1-16-8192";//medium 
	//WCHAR wszIntegritySid[20] = L"S-1-16-12288"; high
	//WCHAR wszIntegritySid[20] = L"S-1-16-16384"; //system

	fRet = OpenProcessToken(GetCurrentProcess(),
		TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
		&hToken);
	if (!fRet)
	{
		printf("[-] OpenProcessToken - failed %u\n", GetLastError());
		//goto CleanExit;
	}
	fRet = DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation, TokenPrimary, &hNewToken);
	if (!fRet)
	{
		printf("[-] DuplicateTokenEx - failed %u\n", GetLastError());
		//goto CleanExit;
	}
	fRet = ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid);
	if (!fRet)
	{
		printf("[-] ConvertStringSidToSid - failed %u\n", GetLastError());
		//goto CleanExit;
	}
	TIL.Label.Attributes = SE_GROUP_INTEGRITY;
	TIL.Label.Sid = pIntegritySid;
	fRet = SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL,
		sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid));
	if (!fRet)
	{
		printf("[-] SetTokenInformation - failed %u\n", GetLastError());
		//goto CleanExit;
	}
	fRet = CreateProcessAsUserW(hNewToken, NULL, wszProcessName,
		NULL, NULL, FALSE, 0,
		NULL, NULL, (LPSTARTUPINFOW)&StartupInfo, &ProcInfo);

}













//void change_intrg_of_file(const char* path, MANDATORY_LEVEL integrity)
/*void change_intrg_of_file(const char* integrity)
{
	SECURITY_ATTRIBUTES sa = { 0 };
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	 LPCSTR wszSacl = "S:(ML;;NR;;;LW)";
	if (ConvertStringSecurityDescriptorToSecurityDescriptor(wszSacl, SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL))
	{
		LPCSTR wszFilename = "C:\\Users\\Elvin\\Documents\\testIntegrity\\jr.txt";
		HANDLE h = CreateFile((LPCSTR)wszFilename, READ_CONTROL|WRITE_DAC, 0, &sa, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, NULL);
		DWORD dwErr = ERROR_SUCCESS;
		//PSECURITY_DESCRIPTOR pSD = NULL;
		PACL pSacl = NULL;
		BOOL fSaclPresent = FALSE;
		BOOL fSaclDefaulted = FALSE;
		if (GetSecurityDescriptorSacl((sa.lpSecurityDescriptor), &fSaclPresent, &pSacl, &fSaclDefaulted)) {
			dwErr = SetNamedSecurityInfoW(
				(LPWSTR)wszFilename,
				SE_FILE_OBJECT,
				DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
				NULL, NULL, NULL,
				pSacl);

			if (dwErr == ERROR_SUCCESS) {
				std::cout << "Success!" << std::endl;
				LocalFree((sa.lpSecurityDescriptor));
			}
		}
		LocalFree((sa.lpSecurityDescriptor));
	}
	else
	{
		printf("f");
	}
	/*
	LPCWSTR INTEGRITY_SDDL_SACL_W = NULL;
	//if (integrityLvl == L"Untrusted")
	if(!strcmp(integrity,"Untrusted"))
		INTEGRITY_SDDL_SACL_W = L"";
	else if (!strcmp(integrity, "Low"))
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;LW)";
	else if (!strcmp(integrity, "Medium"))
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;ME)";
	else if (!strcmp(integrity, "High"))
		INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;HI)";
	

	DWORD dwErr = ERROR_SUCCESS;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pSacl = NULL;
	BOOL fSaclPresent = FALSE;
	BOOL fSaclDefaulted = FALSE;
	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
		INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, NULL)) {
		if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
		{
			  wchar_t temp[100]= L"C:\\Program Files\\Notepad++\\notepad.exe";
			//memcpy(temp, "C:\\Program Files\\Notepad++\\notepad.exe",strlen("C:\\Program Files\\Notepad++\\notepad.exe")*2);
			dwErr = SetNamedSecurityInfoW(
				temp,
				SE_FILE_OBJECT,
				LABEL_SECURITY_INFORMATION,
				NULL, NULL, NULL,
				pSacl);

			if (dwErr == ERROR_SUCCESS) {
				std::cout << "Success!" << std::endl;
				
				LocalFree(pSD);
			}
		}
		LocalFree(pSD);
	}
	*/
	/*PACL sacl;
	DWORD result = GetNamedSecurityInfoA(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &sacl, NULL);
	
	ACL_SIZE_INFORMATION saclSize;
	GetAclInformation(sacl, &saclSize, sizeof(saclSize), AclSizeInformation);
	
	DWORD count = saclSize.AceCount;
	for (int i = 0; i < count; i++)
	{
		SYSTEM_MANDATORY_LABEL_ACE *pAce;
		GetAce(sacl, i, (LPVOID*)&pAce);
		
		if (pAce->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
		{
			continue;
		}
		PULONG subAuthority;
		subAuthority = GetSidSubAuthority((PSID)&pAce->SidStart, 0);
		switch (integrity)
		{
		case MandatoryLevelLow:
			*subAuthority = SECURITY_MANDATORY_LOW_RID;
			break;
		case MandatoryLevelMedium:
			*subAuthority = SECURITY_MANDATORY_MEDIUM_RID;
			break;
		case MandatoryLevelHigh:
			*subAuthority = SECURITY_MANDATORY_HIGH_RID;
			break;
		case MandatoryLevelSystem:
			*subAuthority = SECURITY_MANDATORY_SYSTEM_RID;
			break;
		default:
			break;
		}
		break;
	}
	SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, sacl);
	
	
}*/