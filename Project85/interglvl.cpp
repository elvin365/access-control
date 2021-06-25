#define _CRT_SECURE_NO_WARNINGS
#include"stllist.h"
void mandatory_integrity(list <info>& gqlist)
{
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		HANDLE hToken;
		PTOKEN_MANDATORY_LABEL mandatoryLabel=NULL;
		MANDATORY_LEVEL integrityLevel;
		PCSTR integrityString;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, it->num_PID);
		if (hProcess == NULL)
		{
			it->integrityString = "No info";
			continue;
		}
		OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
		DWORD returnLength = 0;
		GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLength);// 902 // c NULL возвращает длину буффера
		//mandatoryLabel = (PTOKEN_MANDATORY_LABEL)malloc(returnLength);
		mandatoryLabel =(PTOKEN_MANDATORY_LABEL)LocalAlloc(0, returnLength);
		GetTokenInformation(hToken, TokenIntegrityLevel, mandatoryLabel, returnLength, &returnLength);// теперь,когда длина буфера есть, пишем строку
		unsigned subAuthority = *GetSidSubAuthority(mandatoryLabel->Label.Sid, 0);
		//unsigned subAuthority = *GetSidSubAuthority(PSID(it->SID), 0);
		//printf("%p", subAuthority);
		switch (subAuthority)
		{
		case SECURITY_MANDATORY_UNTRUSTED_RID:
			integrityLevel = MandatoryLevelUntrusted;
			integrityString = "Untrusted";
			//printf("%s\n", integrityString);
			it->integrityString = "Untrusted";
			break;
		case SECURITY_MANDATORY_LOW_RID:
			integrityLevel = MandatoryLevelLow;
			integrityString = "Low";
			//printf("%s\n", integrityString);
			it->integrityString = "Low";
			break;
		case SECURITY_MANDATORY_MEDIUM_RID:
			integrityLevel = MandatoryLevelMedium;
			integrityString = "Medium";
			//printf("%s\n", integrityString);
			it->integrityString = "Medium";
			break;
		case SECURITY_MANDATORY_HIGH_RID:
			integrityLevel = MandatoryLevelHigh;
			integrityString = "High";
			//printf("%s\n", integrityString);
			it->integrityString = "High";
			break;
		case SECURITY_MANDATORY_SYSTEM_RID:
			integrityLevel = MandatoryLevelSystem;
			integrityString = "System";
			//printf("%s\n", integrityString);
			it->integrityString = "System";
			break;
		case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
			integrityLevel = MandatoryLevelSecureProcess;
			integrityString = "Protected";
			//printf("%s\n", integrityString);
			it->integrityString = "Protected";
			break;
		default:
			puts(":(");
		}
		
	}

}

/*void change_integraty(list <info>& gqlist)
{
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		if (it->num_PID ==28040)
		{
			HANDLE token;
			HANDLE primary_token;
			TOKEN_MANDATORY_LABEL TIL = { 0 };
			PSID pIntegritySid = NULL;
			WCHAR wszIntegritySid[20] = L"S-1-16-4096";
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, it->num_PID);
			OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &token);
			DuplicateTokenEx(token,MAXIMUM_ALLOWED,NULL,SecurityImpersonation,TokenPrimary, &primary_token);
			ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid);
			TIL.Label.Attributes = SE_GROUP_INTEGRITY;
			TIL.Label.Sid = pIntegritySid;
			SetTokenInformation(primary_token, TokenIntegrityLevel, &TIL,sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid));
			
		}
	}

}*/

void change_integraty(list <info>& gqlist)
{
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		if (it->num_PID == 29052)
		{
			it->integrityString = "Untrusted";

			PSID sid;
			const char *sidStr;
			if (!strcmp(it->integrityString, "Untrusted"))
			{

				sidStr = "S-1-16-0";
			}
			else
			{
				if (!strcmp(it->integrityString, "Low"))
				{
					sidStr = "S-1-16-4096";
				}
				else
				{
					if (!strcmp(it->integrityString, "Medium"))
					{
						sidStr = "S-1-16-8192";
					}
					else
					{
						if (!strcmp(it->integrityString, "High"))
						{
							sidStr = "S-1-16-12288";
						}
						else
						{
							if (!strcmp(it->integrityString, "System"))
							{
								sidStr = "S-1-16-16384";
							}
							else
							{
								sidStr = "S-1-16-20480";
							}
						}
					}
				}
			}



			ConvertStringSidToSidA((LPSTR)sidStr, &sid);

			DWORD returnLength = 0;
			//HANDLE hToken;
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, it->num_PID);
			//HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, it->num_PID);
			PTOKEN_MANDATORY_LABEL mandatoryLabel = NULL;
			if (hProcess == NULL)
			{
				continue;
			}
			OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hProcess);
			//OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT, &hToken);
			GetTokenInformation(hProcess, TokenIntegrityLevel, NULL, 0, &returnLength);// 902 // c NULL возвращает длину буффера
			mandatoryLabel = (PTOKEN_MANDATORY_LABEL)malloc(returnLength);
			GetTokenInformation(hProcess, TokenIntegrityLevel, mandatoryLabel, returnLength, &returnLength);
			mandatoryLabel->Label.Attributes = SE_GROUP_INTEGRITY;
			mandatoryLabel->Label.Sid = sid;
			sprintf(it->SID, "%s", (char*)sid);
			SetTokenInformation(hProcess, TokenIntegrityLevel, mandatoryLabel, returnLength);
			CloseHandle(hProcess);
			
			//CloseHandle(hToken);
		}


		//the_username_sid(gqlist);
	}
}
