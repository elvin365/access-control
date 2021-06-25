#include"stllist.h"
int main()
{
	setlocale(LC_ALL, "Russian");

	list <info> gqlist;
	list <info_file> gqlist2;
	get_first_three(gqlist);
	know_your_parent(gqlist);
	the_name_of_parent(gqlist);
	the_username_sid(gqlist);
	x_32_64(gqlist);
	get_dep_aslr(gqlist);
	about_dll(gqlist);
	mandatory_integrity(gqlist);

	change_integraty(gqlist);

	//give_acl(gqlist);
	//acl_ace(gqlist2,"C:\\Users\\Elvin\\Documents\\testIntegrity\\SETME.txt");
	acl_ace(gqlist2, "C:\\Program Files\\IDA Demo 7.0\\ida.exe");
	CreateFilesLowHighIntg();
	//setLevel();
	//change_intrg_of_file("C:\\Users\\Elvin\\Documents\\testIntegrity\\hi.txt", MandatoryLevelLow);
	//change_intrg_of_file("Low");
	/*list <info> gqlist2;
	
	get_first_three(gqlist2);
	know_your_parent(gqlist2);
	the_name_of_parent(gqlist2);
	the_username_sid(gqlist2);
	x_32_64(gqlist2);
	get_dep_aslr(gqlist2);
	about_dll(gqlist2);
	mandatory_integrity(gqlist2);
	change_integraty(gqlist2);*/

	//list <info> ::iterator lit;
	/*for (lit = gqlist.begin(); lit != gqlist.end(); ++lit)
	{
		GetUserFromProcess(lit->num_PID);

	}*/

	list <info> ::iterator it;
	int counting1 = 0;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		//cout << "ProcessID " << it->num_PID << " ImageFileName " << it->name_PID << '\n';
		//printf("ProcessID : %d  ImageFileName: %ls \n", it->num_PID, it->name_PID );// show me the procces id and its name

		//this is the exe path
		//if(!(it->path==NULL))
		//printf("EXE Path: %s\n", it->path);

		//printf("Is the numer of parent process id %d\n", it->num_par_PID);// the pid of parent
		//printf("Parent's name %s\n", it->par_name);// the name of parent proc
		//printf("    Owner   %20s | SID: %50s\n", ownerName, sidDisplay);
		//if (!(it->path == NULL))
		//printf("    Owner   %20s | SID: %50s\n", it->ownerName, it->SID);
		//printf("%d\n", it->x_bit);
		//printf("%s" "%s\n", it->DEP, it->ASLR);

		/*int i = 0;
		while (strcmp(it->DLL[i], "\0"))
		{
			printf("%s %d \n", it->DLL[i],it->num_PID);
			i++;

		}
		puts("\n");*/
		//printf("%s\n",it->integrityString);

//		printf("%s %s \n", it->usr_acl, it->acl);

		
	}
	/*list <info_file> ::iterator lit;
	int i = 0;
	for (lit = gqlist2.begin(); lit != gqlist2.end(); ++lit)
	{
		printf("%s\n\n", lit->owner);
		while (strcmp(lit->ACE[i], "\0"))
		{
			printf("%s\n", lit->ACE[i]);
			i++;
		}
	}*/
	return 0;
}