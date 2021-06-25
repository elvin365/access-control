#define _CRT_SECURE_NO_WARNINGS
#include"stllist.h"
#include<tchar.h>
#define _WIN32_WINNT 0x0602
void get_dep_aslr(list <info>& gqlist)
{

	list <info> ::iterator lit;

	for (lit = gqlist.begin(); lit != gqlist.end(); ++lit)
	{
		//bool k1=GetProcessMitigationPolicy(OpenProcess(PROCESS_QUERY_INFORMATION, false, lit->num_PID), ProcessDEPPolicy, lpBuffer,sizeof(lpBuffer));
		//int k = 0;
		PROCESS_MITIGATION_DEP_POLICY policy;
		bool k=GetProcessMitigationPolicy(OpenProcess(PROCESS_QUERY_INFORMATION, false, lit->num_PID), ProcessDEPPolicy, &policy, sizeof(policy));
		if (k == 1)
		{
			sprintf(lit->DEP, "%s", "Yes");
		}
		else
		{
			sprintf(lit->DEP, "%s", "No");

		}
		
		PROCESS_MITIGATION_ASLR_POLICY policy1;
		bool k1= GetProcessMitigationPolicy(OpenProcess(PROCESS_QUERY_INFORMATION, false, lit->num_PID), ProcessASLRPolicy, &policy1, sizeof(policy));
		if (k1 == 1)
		{
			sprintf(lit->ASLR, "%s", "Yes");
		}
		else
		{
			sprintf(lit->ASLR, "%s", "No");

		}
	}
	about_dll(gqlist);
}
void about_dll(list <info>& gqlist)
{
	list <info> ::iterator it;
	HANDLE hSnap;
	
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		int i = 0;
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, it->num_par_PID);
		if (hSnap == NULL)
		{
			continue;
		}
		else
		{
			memset(it->DLL[i], 0, 30);
			MODULEENTRY32 mod;
			if (Module32First(hSnap, &mod))
			{
				//m_List1.AddString(mod.szExePath);
				char k1[30]="\0";
				sprintf(k1, "%s", mod.szModule);
				if (!strstr(k1, "exe"))
				{
					sprintf(it->DLL[i], "%s", mod.szModule);
					i++;
					memset(it->DLL[i], 0, 30);
				}
				
				while (Module32Next(hSnap, &mod))
				{
					//m_List1.AddString(mod.szExePath);
					if (strstr(mod.szModule, "exe"))
						continue;
					sprintf(it->DLL[i], "%s", mod.szModule);
					i++;
					memset(it->DLL[i], 0, 30);
				}
			}
			CloseHandle(hSnap);
		}
	}
	/*list <info> ::iterator it;
	HANDLE hSnap;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
			it->num_par_PID);
		if (hSnap == NULL)
		{
			continue;
		}
		else
		{
			MODULEENTRY32 mod;
			for (BOOL i = Module32First(hSnap, &mod); i; i = Module32Next(hSnap, &mod))
			{
				if (strstr(mod.szModule, "exe"))
					continue;
				memset(it->DLL, 0, 30);
				sprintf(it->DLL, "%s", mod.szModule);
				//printf("%s\n", mod.szModule);
			}
		}
	CloseHandle(hSnap);

	}*/
}
/*void about_dll(list <info>& gqlist)
{
	list <info> ::iterator lit;
	DWORD* mass;
	DWORD cbNeeded, cProcesses;
	mass = (DWORD*)malloc(1*sizeof(DWORD));
	int i = 0;
	for (lit = gqlist.begin(); lit != gqlist.end(); ++lit)
	{
		mass[i] = lit->num_PID;
		mass = (DWORD*)realloc(mass, sizeof(DWORD)*(i + 2));
		i++;
	}
	int k = 0;
	EnumProcesses(mass, sizeof(mass)*i, &cbNeeded);

	// Calculate how many process identifiers were returned.
		cProcesses = cbNeeded / sizeof(DWORD);
		for (i = 0; i < cProcesses; i++)
		{
			//PrintModules(aProcesses[i]);
			about_dll2(mass[i]);
		}
}

void about_dll2(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, processID);
	// Get a list of all the modules in this process.
	if (NULL == hProcess)
		return;
	
	//GetModuleHandleExA(NULL, "chrome.exe", hMods);
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
			}
		}
	}
	int k = GetLastError();
}*/

