#pragma once
#include<list>
#include<iterator>
#include<iostream>
#include<windows.h>
#include<stdio.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include<lm.h>
#include<aclapi.h>
#include<sddl.h>
//#define _WIN32_WINNT 0x0500
using namespace std;

struct info
{
	 wchar_t name_PID[100]; // the name of process
	 //maybe DWORD not unsigned
	unsigned num_PID; // the id of the proc
	 char* path;// the way like C://
	 char par_name[100]; // the name of parent
	unsigned num_par_PID;// the id of the parent
	 char ownerName[256]="\0"; // host/adm/elv
	 char* SID;
	unsigned x_bit;
	//bool DEP;
	char DEP[4];
	//bool ASLR;
	char ASLR[4];
	char DLL[30][1000];
	PCSTR integrityString;
	// char* integrityString;
	char acl[256]="\0";
	char usr_acl[100]="\0";
	
};
struct info_file
{
	char owner[256] = "\0";
	char* SID;
	char ACE[100][100] = { "\0","\0" };
	const char *intstring;
};
void 	get_first_three(list <info>&);
void	exe_path(list <info>&);// get the exe
void	know_your_parent(list <info>&);
void	the_name_of_parent(list <info>&);
void	the_username_sid(list <info>&);
void	x_32_64(list <info>&);
void	get_dep_aslr(list <info>&);
void	about_dll(list <info>&);
//void	about_dll2(DWORD);
void	mandatory_integrity(list <info>&);
void	change_integraty(list <info>&);
//void	give_name_acl(list<info>&); 
//void	give_acl(list<info>&);
void	acl_ace(list<info_file>&,const char*);
void	CreateFilesLowHighIntg(void);
//void	setLevel();
//void	change_intrg_of_file(const char*, MANDATORY_LEVEL);
//void	change_intrg_of_file(const char*);
//HRESULT GetUserFromProcess(const DWORD procId);
//BOOL GetLogonFromToken(HANDLE hToken);

