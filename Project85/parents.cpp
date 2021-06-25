#include"stllist.h"
DWORD counting = 0;

void know_your_parent(list <info> &gqlist)
{
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		HANDLE h = NULL;
		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32);
		h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Process32First(h, &pe))
		{
			do
			{
				if (pe.th32ProcessID == it->num_PID)
				{
					it->num_par_PID = pe.th32ParentProcessID;
					break;
				}
			} while (Process32Next(h, &pe));
		}
		CloseHandle(h);
				
	}
	
}
void the_name_of_parent(list <info>& gqlist)
{
	//DWORD PID = 1337; // something here
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		PROCESSENTRY32 peInfo;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, it->num_par_PID);
		if (hSnapshot)
		{
			peInfo.dwSize = sizeof(peInfo); // this line is REQUIRED
			BOOL nextProcess = Process32First(hSnapshot, &peInfo);
			bool found = false;
			while (nextProcess)
			{
				if (peInfo.th32ProcessID == it->num_par_PID)
				{
					found = true;
					break;
				}
				nextProcess = Process32Next(hSnapshot, &peInfo);
			}
			if (found)
			{
				//printf("%d  %s\n",counting, peInfo.szExeFile);
				memset(it->par_name, 0, strlen(it->par_name));
				//memcpy(it->par_name, peInfo.szExeFile, strlen(peInfo.szExeFile));
				sprintf_s(it->par_name, "%s", peInfo.szExeFile);
				//printf("%d  %s\n",counting, it->par_name);
				//counting++;

			}
			else
			{
				memset(it->par_name, 0, strlen(it->par_name));
				sprintf_s(it->par_name, "%s", "No parent proc aviable");
			}
			CloseHandle(hSnapshot);
		}
		//printf("%s\n",it->par_name);
		

	}
}


