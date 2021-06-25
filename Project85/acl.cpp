#define _CRT_SECURE_NO_WARNINGS
#include"stllist.h"
#include<WinError.h>
void acl_ace(list <info_file>& gqlist2, const char* path)
{

	struct info_file name;

	PSID ownerSid;
	PSID pSid;
	PACL dacl;
	PACL sacl;
	PSECURITY_DESCRIPTOR sd;
	DWORD result;
	
	GetNamedSecurityInfoA(path, SE_FILE_OBJECT, GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &ownerSid, NULL, &dacl, &sacl, &sd);

	SID_NAME_USE type;
	DWORD strsize = MAX_PATH;
	//char ownerName[MAX_PATH];
	char ownerDomain[MAX_PATH];
	if (LookupAccountSidA(NULL, ownerSid, name.owner, &strsize, ownerDomain, &strsize, &type))
	{
		char *sidDisplay;

		//			memset(it->SID, 0, 256);
		ConvertSidToStringSidA(ownerSid, &sidDisplay);
		name.SID = sidDisplay;
		printf("    Owner   %20s | SID: %50s\n", name.owner, name.SID);
		printf("    Owner   %20s | SID: %50s\n", name.owner, name.SID);
	}
	else
	{
		name.SID = NULL;
		memset(name.owner, 0, 256);
		memcpy(name.owner, "NoOwner", strlen("NoOwner"));
	}
	//gqlist2.push_back(name);
	PACL ACL_struct;
	PSECURITY_DESCRIPTOR SecDescrpt;
	if ((GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &ACL_struct, NULL, &SecDescrpt) == ERROR_SUCCESS))
	{


		//GetNamedSecurityInfoA(it->path, SE_FILE_OBJECT, GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
			//NULL, NULL, &ACL_struct, NULL, &SecDescrpt);
		if (ACL_struct == NULL)
		{
			//name.ACE[0] = "No ACL info";
			sprintf(name.ACE[0], "%s", "No ACL info");
			return;
		}
		ACL_SIZE_INFORMATION ACL_Info;
		if (GetAclInformation(ACL_struct, &ACL_Info, sizeof(ACL_Info), AclSizeInformation))
		{
			for (DWORD i = 0; i < ACL_Info.AceCount; i++)
			{
				ACCESS_ALLOWED_ACE *ACE = NULL;
				if (GetAce(ACL_struct, i, (LPVOID*)&ACE))
				{
					//(PSID *)&(ACE)->SidStart; this holds SID
					PSID *pSID = (PSID *)&((ACCESS_ALLOWED_ACE *)ACE)->SidStart;
					wchar_t wUser[MAX_PATH], wDomain[MAX_PATH];
					SID_NAME_USE sidNameUse;
					DWORD dwLen = MAX_PATH;
					if (LookupAccountSidW(NULL, pSID, wUser, (LPDWORD)&dwLen, wDomain, &dwLen, &sidNameUse))
					{
						LPWSTR stringSid = NULL;
						ConvertSidToStringSidW(&ACE->SidStart, &stringSid);
						if ((ACE->Header.AceType == ACCESS_ALLOWED_ACE_TYPE))
						{
							sprintf(name.ACE[i], "%s", "Allowed ACE");
							i++;
							//sprintf(it->usr_acl, "%s", wUser);
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if (ACE->Header.AceType == ACCESS_DENIED_ACE_TYPE)
						{
							sprintf(name.ACE[i], "%s", "Denied ACE");
							i++;
							//sprintf(it->usr_acl, "%s", wUser);
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if (ACE->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
						{
							sprintf(name.ACE[i], "%s", "System Alarm ACE");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if (ACE->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
						{
							sprintf(name.ACE[i], "%s", "System Audit ACE");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}

						if (((ACE)->Mask & WRITE_OWNER) == WRITE_OWNER)
						{
							sprintf(name.ACE[i], "%s", "Change Owner");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if ((ACE->Mask& WRITE_DAC) == WRITE_DAC)
						{
							sprintf(name.ACE[i], "%s", "Write DAC");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if ((ACE->Mask & DELETE) == DELETE)
						{
							sprintf(name.ACE[i], "%s", "Delete");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						//this->aclList_.emplace(wUser, L"Delete");
						if ((ACE->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
						{
							sprintf(name.ACE[i], "%s", "Read");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if ((ACE->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
						{
							sprintf(name.ACE[i], "%s", "Write");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if ((ACE->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
						{
							sprintf(name.ACE[i], "%s", "Execute");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if ((ACE->Mask  & SYNCHRONIZE) == SYNCHRONIZE)
						{
							sprintf(name.ACE[i], "%s", "Synchronize");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}
						if ((ACE->Mask  & READ_CONTROL) == READ_CONTROL)
						{
							sprintf(name.ACE[i], "%s", "Read control");
							i++;
							/*char buf[100] = "\0";
							size_t len = wcstombs(buf, wUser, wcslen(wUser));
							if (len > 0u)
								buf[len] = '\0';
							sprintf(it->usr_acl, "%s", buf);*/
						}


					}

				}


			}
		}

	}
	gqlist2.push_back(name);

}
/*void give_name_acl(list<info>& gqlist)
{
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		PSID pOwnerSid = NULL;           // SID of file/folder/key
		PSECURITY_DESCRIPTOR pSD = NULL; // security descriptor (ptr)
		if (GetNamedSecurityInfoW((LPCWSTR)(it->path), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
			&pOwnerSid, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS) {
			if (pSD != NULL) 
			{
				wchar_t wUser[MAX_PATH], wDomain[MAX_PATH];
				DWORD dwLen = MAX_PATH;
				SID_NAME_USE sidNameUse;
				if (LookupAccountSidW(NULL, pOwnerSid, wUser, (LPDWORD)&dwLen, wDomain, &dwLen, &sidNameUse)) {
					LPWSTR stringSid = NULL;
					ConvertSidToStringSidW(pOwnerSid, &stringSid);
					sprintf(it->ownerName, "%s", wUser);
					sprintf(it->SID, "%s", stringSid);
					
				}
			}
		}
	}
}
/*void give_acl(list<info>& gqlist)
{

	PACL ACL_struct;
	PSECURITY_DESCRIPTOR SecDescrpt;
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		if (it->path == NULL)
		{
			continue;
		}
		
		//if ((GetNamedSecurityInfoW((LPCWSTR)it->path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &ACL_struct, NULL, &SecDescrpt) == ERROR_SUCCESS))
		if((GetNamedSecurityInfoA(it->path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,NULL, NULL, &ACL_struct, NULL, &SecDescrpt)==ERROR_SUCCESS))
		{


			//GetNamedSecurityInfoA(it->path, SE_FILE_OBJECT, GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
				//NULL, NULL, &ACL_struct, NULL, &SecDescrpt);
			if (ACL_struct == NULL)
			{
				continue;
			}
			ACL_SIZE_INFORMATION ACL_Info;
				if (GetAclInformation(ACL_struct, &ACL_Info, sizeof(ACL_Info), AclSizeInformation))
				{
					for (DWORD i = 0; i < ACL_Info.AceCount; i++)
					{
						ACCESS_ALLOWED_ACE *ACE = NULL;
						if (GetAce(ACL_struct, i, (LPVOID*)&ACE))
						{
							//(PSID *)&(ACE)->SidStart; this holds SID
							PSID *pSID = (PSID *)&((ACCESS_ALLOWED_ACE *)ACE)->SidStart;
							wchar_t wUser[MAX_PATH], wDomain[MAX_PATH];
							SID_NAME_USE sidNameUse;
							DWORD dwLen = MAX_PATH;
							if (LookupAccountSidW(NULL, pSID, wUser, (LPDWORD)&dwLen, wDomain, &dwLen, &sidNameUse))
							{
								LPWSTR stringSid = NULL;
								ConvertSidToStringSidW(&ACE->SidStart, &stringSid);
								if ((ACE->Header.AceType == ACCESS_ALLOWED_ACE_TYPE))
								{
									sprintf(it->acl, "%s", "Allowed ACE");
									//sprintf(it->usr_acl, "%s", wUser);
									char buf[100]="\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if (ACE->Header.AceType == ACCESS_DENIED_ACE_TYPE)
								{
									sprintf(it->acl, "%s", "Denied ACE");
									//sprintf(it->usr_acl, "%s", wUser);
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if (ACE->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
								{
									sprintf(it->acl, "%s", "System Alarm ACE");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if (ACE->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
								{
									sprintf(it->acl, "%s", "System Audit ACE");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}

								if (((ACE)->Mask & WRITE_OWNER) == WRITE_OWNER)
								{
									sprintf(it->acl, "%s", "Change Owner");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if ((ACE->Mask& WRITE_DAC) == WRITE_DAC)
								{
									sprintf(it->acl, "%s", "Write DAC");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if ((ACE->Mask & DELETE) == DELETE)
								{
									sprintf(it->acl, "%s", "Delete");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								//this->aclList_.emplace(wUser, L"Delete");
								if ((ACE->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
								{
									sprintf(it->acl, "%s", "Read");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if ((ACE->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
								{
									sprintf(it->acl, "%s", "Write");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if ((ACE->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
								{
									sprintf(it->acl, "%s", "Execute");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if ((ACE->Mask  & SYNCHRONIZE) == SYNCHRONIZE)
								{
									sprintf(it->acl, "%s", "Synchronize");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}
								if ((ACE->Mask  & READ_CONTROL) == READ_CONTROL)
								{
									sprintf(it->acl, "%s", "Read control");
									char buf[100] = "\0";
									size_t len = wcstombs(buf, wUser, wcslen(wUser));
									if (len > 0u)
										buf[len] = '\0';
									sprintf(it->usr_acl, "%s", buf);
								}


							}

						}


					}
				}
		}
	}
}*/