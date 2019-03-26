#include "driver.h"
#include <wingdi.h>

DWORD winMajor=0,winMinor=0,winBuild=0;
BOOL bNotifyRoutineCreated=FALSE,bDriverInit=FALSE;
LARGE_INTEGER nInHookRefCount={{0,0}};
UINT rseed=0;

PSSMSG pSSBuffer=NULL;
HOOKDATA kHooks;

//System Func Offsets NtQueryInformationThread
typedef NTSTATUS (DDKAPI *tNtQueryInformationThread)(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass,
PVOID ThreadInformation,ULONG_PTR ThreadInformationLength,PULONG_PTR ReturnLength);

DWORD NtQueryInformationThreadOffset=0;
PVOID *NtQueryInformationThreadAddress=NULL;
tNtQueryInformationThread pNtQueryInformationThread=NULL;
tNtQueryInformationThread pSecureNtQueryInformationThread=NULL;

//System Func Offsets NtDeviceIoControlFile
typedef NTSTATUS (DDKAPI *tNtDeviceIoControlFile)(HANDLE FileHandle,HANDLE Event,
PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,ULONG_PTR IoControlCode,
PVOID InputBuffer,ULONG_PTR InputBufferLength,PVOID OutputBuffer,ULONG_PTR OutputBufferLength);

DWORD NtDeviceIoControlFileOffset=0;
PVOID *NtDeviceIoControlFileAddress=NULL;
tNtDeviceIoControlFile pNtDeviceIoControlFile=NULL;
tNtDeviceIoControlFile pSecureNtDeviceIoControlFile=NULL;

//System Func Offsets NtQuerySystemInformation
typedef NTSTATUS (DDKAPI *tNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,
PVOID SystemInformation,ULONG_PTR SystemInformationLength,PULONG_PTR ReturnLength);

DWORD NtQuerySystemInformationOffset=0;
PVOID *NtQuerySystemInformationAddress=NULL;
tNtQuerySystemInformation pNtQuerySystemInformation=NULL;
tNtQuerySystemInformation pSecureNtQuerySystemInformation=NULL;

//System Func Offsets NtQueryVirtualMemory
typedef NTSTATUS (DDKAPI *tNtQueryVirtualMemory)(HANDLE ProcessHandle,PVOID BaseAddress,MEMORY_INFORMATION_CLASS MemoryInformationClass,
  PVOID MemoryInformation,ULONG_PTR MemoryInformationLength,PULONG_PTR ReturnLength);

DWORD NtQueryVirtualMemoryOffset=0;
PVOID *NtQueryVirtualMemoryAddress=NULL;
tNtQueryVirtualMemory pNtQueryVirtualMemory=NULL;
tNtQueryVirtualMemory pSecureNtQueryVirtualMemory=NULL;

//System Func Offsets NtGdiBitBlt
typedef NTSTATUS (DDKAPI *tNtGdiBitBlt)(HDC hDCDest,INT XDest,INT YDest,INT Width,
INT Height,HDC hDCSrc,INT XSrc,INT YSrc,DWORD ROP,IN DWORD crBackColor,IN FLONG fl);

DWORD NtGdiBitBltOffset=0;
PVOID *NtGdiBitBltAddress=NULL;
tNtGdiBitBlt pNtGdiBitBlt=NULL;
tNtGdiBitBlt pSecureNtGdiBitBlt=NULL;

//System Func Offsets NtGdiSetDIBitsToDeviceInternal
typedef NTSTATUS (DDKAPI *tNtGdiSetDIBitsToDeviceInternal)(HDC hdcDest,INT XDest,INT YDest,INT Width,INT Height,
INT XSrc,INT YSrc,DWORD iStartScan,DWORD cNumScan,LPBYTE pInitBits,LPBITMAPINFO pbmi,
DWORD iUsage,UINT cjMaxBits,UINT cjMaxInfo,BOOL bTransformCoordinates,HANDLE hcmXform);

DWORD NtGdiSetDIBitsToDeviceInternalOffset=0;
PVOID *NtGdiSetDIBitsToDeviceInternalAddress=NULL;
tNtGdiSetDIBitsToDeviceInternal pNtGdiSetDIBitsToDeviceInternal=NULL;
tNtGdiSetDIBitsToDeviceInternal pSecureNtGdiSetDIBitsToDeviceInternal=NULL;

PVOID *KeBugCheckExOrig=0;

typedef VOID (DDKAPI *tRtlCaptureContext)(PCONTEXT ContextRecord);
tRtlCaptureContext pRtlCaptureContext=NULL;
tRtlCaptureContext pSecureRtlCaptureContext=NULL;
PVOID *RtlCaptureContextOrig=0;
DWORD RtlCaptureContextSize=0;

typedef VOID (FASTCALL *tKiRetireDpcList)(PKPRCB Prcb);
tKiRetireDpcList pKiRetireDpcList=NULL;
tKiRetireDpcList pSecureKiRetireDpcList=NULL;
PVOID *KiRetireDpcListOrig=0;
DWORD KiRetireDpcListSize=0;

static CHAR sserial[50]={0};//short serial
static CHAR lserial[100]={0};//large serial
static char Format[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

WCHAR sCreateDeviceName[]=L"\\Device\\mydriver";
WCHAR sCreateSymbolicLinkName[]=L"\\DosDevices\\mydriver";

PVOID RevBaseAddress=NULL;
DWORD RevRegionSize=0;

KSPIN_LOCK IntLock;

////////////////////////////////////////////////////////
// Added for x64
////////////////////////////////////////////////////////

PVOID FindFreeExecSpace(PVOID ImageBase,DWORD Needed){
  DWORD i;
  PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)ImageBase;
  if(!pDosHeader||pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE){
    return NULL;
  }
  PIMAGE_NT_HEADERS pNtHeader=(PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew+(PBYTE)ImageBase);
  if(pNtHeader->Signature!=IMAGE_NT_SIGNATURE){
	  return NULL;
  }
  for(i=0;i<pNtHeader->FileHeader.NumberOfSections;++i){
    PIMAGE_SECTION_HEADER pSec=&IMAGE_FIRST_SECTION64(pNtHeader)[i];
    if(pSec->Characteristics&IMAGE_SCN_CNT_CODE){
      PBYTE pAddress,pBaseAddress=(PBYTE)ImageBase+pSec->VirtualAddress;
      DWORD Blanks=0,Size=max(pSec->Misc.VirtualSize,pSec->SizeOfRawData);
      for(pAddress=pBaseAddress+Size;((pAddress>pBaseAddress)&&(Blanks<Needed));pAddress--){
        if(!*pAddress)
          Blanks++;
        else
          Blanks=0;
      }
      if(Blanks==Needed){
        return pAddress;
      }
    }
  }
	return NULL;
}

VOID DDKAPI HideDriver(PDRIVER_OBJECT DriverObject){
  KIRQL OldIrql=KeRaiseIrqlToDpcLevel();
  PLDR_DATA_TABLE_ENTRY DriverEntry=DriverObject->DriverSection;
  RemoveEntryList(&DriverEntry->InLoadOrderLinks);
  InitializeListHead(&DriverEntry->InLoadOrderLinks);
  KeLowerIrql(OldIrql);
}

LARGE_INTEGER DDKAPI ExInterlockedIncrement(PLARGE_INTEGER Addend){
  LARGE_INTEGER inc;inc.QuadPart=1;
  return ExInterlockedAddLargeInteger(Addend,inc,&IntLock);
}

LARGE_INTEGER DDKAPI ExInterlockedDecrement(PLARGE_INTEGER Addend){
  LARGE_INTEGER inc;inc.QuadPart=-1;
  return ExInterlockedAddLargeInteger(Addend,inc,&IntLock);
}

PVOID DDKAPI DecodeSSDTAddress(PVOID pBase,PVOID *pAddress,BOOL bHi){
  if(!MmIsAddressValid(pAddress)){
    return NULL;
  }
  PULARGE_INTEGER pLargeInteger=(PULARGE_INTEGER)pAddress;
  if(winMajor<6){//XP - 2003
    if(bHi)return (pBase+(((LONG)pLargeInteger->HighPart>>4)<<4));
    return (pBase+(((LONG)pLargeInteger->LowPart>>4)<<4));
  }
  //Vista and New
  if(bHi)return (pBase+((LONG)pLargeInteger->HighPart>>4));
  return (pBase+((LONG)pLargeInteger->LowPart>>4));
}

DWORD DDKAPI EncodeSSDTAddress(PVOID pBase,PVOID *pAddress,PVOID pNewAddress,BOOL bHi){
  //need to be alligned!
  if(((ULONGLONG)pNewAddress&0xF)||((pNewAddress-pBase)>0x0FFFFFFF)){
    return 0;
  }
  if(!MmIsAddressValid(pAddress)){
    return 0;
  }
  PULARGE_INTEGER pLargeInteger=(PULARGE_INTEGER)pAddress;
  DWORD relOffset=(DWORD)(pNewAddress-pBase);
  if(winMajor<6){//XP - 2003
    if(bHi)return (relOffset|(pLargeInteger->HighPart&0xF));
    return (relOffset|(pLargeInteger->LowPart&0xF));
  }
  //Vista and New
  if(bHi)return ((relOffset<<4)|(pLargeInteger->HighPart&0xF));
  return ((relOffset<<4)|(pLargeInteger->LowPart&0xF));
}

BOOL DDKAPI CompareMemory(LPBYTE bAddress,LPBYTE bCode,UINT uSize,BOOL bPattern){
  UINT i;
  for(i=0;i<uSize;i++,bCode++,bAddress++){
    if((*bAddress!=*bCode)&&(!bPattern||*bCode!=0xFF))
      return FALSE;
  }
  return TRUE;
}

ULONGLONG DDKAPI FindCodeAddress(ULONGLONG dwStart,ULONGLONG dwEnd,LPBYTE bCode,UINT CodeSize,INT OpcodeNum,BOOL bPattern){
  ULONGLONG i;
  for(i=dwStart;(i+CodeSize)<dwEnd;i++){
    if(CompareMemory((LPBYTE)i,bCode,CodeSize,bPattern))
      return (ULONGLONG)(i+OpcodeNum);
  }
  return 0;
}

PSYSTEM_MODULE_INFORMATION_64 DDKAPI GetSystemModuleInformation(){
  PSYSTEM_MODULE_INFORMATION_64 pSMInfo=NULL;
  NTSTATUS Status=STATUS_NO_MEMORY;
  ULONG SMInfoLen=1000;
  do{
    pSMInfo=ExAllocatePoolWithTag(PagedPool,SMInfoLen,0);
    if(!pSMInfo)
      break;
    Status=ZwQuerySystemInformation(SystemModuleInformation,pSMInfo,SMInfoLen,&SMInfoLen);
    if(!NT_SUCCESS(Status)){
      ExFreePoolWithTag(pSMInfo,0);
      pSMInfo=NULL;
    }
  }while(Status==STATUS_INFO_LENGTH_MISMATCH);
  return pSMInfo;
}

PVOID DDKAPI GetModuleBaseAddressAndSize(PSYSTEM_MODULE_INFORMATION_64 pSMInfo,PVOID pAddress,PULONG pSize,PCHAR pName){
  if(pSMInfo){
    if(pAddress){
      UINT i;
      for(i=0;i<pSMInfo->Count;i++){
        if(pAddress>=pSMInfo->Module[i].Base&&pAddress<=(pSMInfo->Module[i].Base+pSMInfo->Module[i].Size)){
          if(pName)
            strcpy(pName,&pSMInfo->Module[i].ImageName[pSMInfo->Module[i].PathLength]);
          if(pSize)
            *pSize=pSMInfo->Module[i].Size;
          return pSMInfo->Module[i].Base;
        }
      }
    }else{
      if(pSize)
        *pSize=pSMInfo->Module[0].Size;
      return pSMInfo->Module[0].Base;
    }
  }
  return NULL;
}

NTSTATUS DDKAPI CheckIfIs(LPSTR sFileName,LPCSTR sNeedFile){
  LPSTR sFile=sFileName;
  for(;*sFile;sFile++)
    if((unsigned)(*sFile-0x41)<0x1Au)*sFile|=0x20;
  if(strstr(sFileName,sNeedFile))
    return TRUE;
  return FALSE;
}

BOOL DDKAPI ImageFullPath(PEPROCESS eprocess,PCHAR fullname){
  BOOL ret=FALSE;BYTE buffer[sizeof(UNICODE_STRING)+MAX_PATH*sizeof(WCHAR)];
  HANDLE handle;DWORD returnedLength=0;ANSI_STRING DestinationString;
  if(NT_SUCCESS(ObOpenObjectByPointer(eprocess,OBJ_KERNEL_HANDLE,NULL,GENERIC_READ,0,KernelMode,&handle))){
    if(NT_SUCCESS(ZwQueryInformationProcess(handle,ProcessImageFileName,buffer,sizeof(buffer),&returnedLength))){
      RtlUnicodeStringToAnsiString(&DestinationString,(UNICODE_STRING*)buffer,TRUE);
      strncpy(fullname,DestinationString.Buffer,DestinationString.Length);ret=TRUE;
      fullname[DestinationString.Length]=0;RtlFreeAnsiString(&DestinationString);
    }
    ZwClose(handle);
  }
  return ret;
}

BOOL DDKAPI ImageFileName(PEPROCESS eprocess,PCHAR filename){
  CHAR sImageFullPath[MAX_PATH]={0};
  if(ImageFullPath(eprocess,sImageFullPath)){
    PCHAR pIFN=sImageFullPath,pIFP=sImageFullPath;
    while(*pIFP)if(*(pIFP++)=='\\')pIFN=pIFP;
    strcpy(filename,pIFN);return TRUE;
  }
  return FALSE;
}

HANDLE DDKAPI GetProcessIdByHandle(HANDLE Process){
  PROCESS_BASIC_INFORMATION_EX ProcessBasicInfo;
  NTSTATUS status=ZwQueryInformationProcess(Process,ProcessBasicInformation,&ProcessBasicInfo,sizeof(ProcessBasicInfo),NULL);
  if(NT_SUCCESS(status))
    return (HANDLE)(ULONGLONG)ProcessBasicInfo.UniqueProcessId;
  return NULL;
}

HANDLE DDKAPI GetThreadIdFromHandle(HANDLE Thread){
  PETHREAD eThread;HANDLE ThreadId;
  NTSTATUS status=ObReferenceObjectByHandle(Thread,0,0,KernelMode,(PVOID)&eThread,NULL);
  if(NT_SUCCESS(status)){
    ThreadId=(HANDLE)PsGetThreadId(eThread);
    ObDereferenceObject(eThread);
    return ThreadId;
  }
  return 0;
}

NTSTATUS DDKAPI TerminateProcessById(HANDLE hProcId){
	HANDLE hProc;OBJECT_ATTRIBUTES oa;CLIENT_ID ClientId;
	InitializeObjectAttributes(&oa,NULL,0,NULL,NULL);
	ClientId.UniqueProcess=(HANDLE)hProcId;
	ClientId.UniqueThread=(HANDLE)0;
	NTSTATUS status=ZwOpenProcess(&hProc,PROCESS_ALL_ACCESS,&oa,&ClientId);
	if(status==STATUS_SUCCESS){
    status=ZwTerminateProcess(hProc,STATUS_SUCCESS);
    ZwClose(hProc);
	}
	return status;
}

ULONG DDKAPI FindProcessId(LPCSTR swName){
  PSYSTEM_PROCESSES_INFORMATION pSPInfo=NULL;
  NTSTATUS Status=STATUS_NO_MEMORY;
  ULONG SPInfoLen=1000,ulProcId=0;CHAR sFileName[MAX_PATH];
  ANSI_STRING DestinationString={MAX_PATH-sizeof(ANSI_NULL),MAX_PATH,sFileName};
  if(!swName)return 0;
  do{
    pSPInfo=ExAllocatePoolWithTag(PagedPool,SPInfoLen,0);
    if(!pSPInfo)
      break;
    Status=ZwQuerySystemInformation(SystemProcessesAndThreadsInformation,pSPInfo,SPInfoLen,&SPInfoLen);
    if(!NT_SUCCESS(Status)){
      ExFreePoolWithTag(pSPInfo,0);
      pSPInfo=NULL;
    }
  }while(Status==STATUS_INFO_LENGTH_MISMATCH);
  if(pSPInfo){
    PSYSTEM_PROCESSES_INFORMATION pSp=pSPInfo;
    do{
      if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&DestinationString,&pSp->ProcessName,FALSE))){
        DestinationString.Buffer[DestinationString.Length]=0;
        if(CheckIfIs(DestinationString.Buffer,swName)){
          ulProcId=pSp->ProcessId;
          break;
        }
      }
      pSp=(PSYSTEM_PROCESSES_INFORMATION)((PBYTE)pSp+pSp->NextEntryDelta);
    }while(pSp->NextEntryDelta!=0);
    ExFreePoolWithTag(pSPInfo,0);
  }
  return ulProcId;
}

BOOL DDKAPI TerminateProcessByName(LPCSTR sName){
  HANDLE dwProcId=(HANDLE)(LONGLONG)FindProcessId(sName);
  if(dwProcId){
    NTSTATUS status=TerminateProcessById(dwProcId);
    return (status==STATUS_SUCCESS);
  }
  return TRUE;
}

NTSTATUS DDKAPI MmAllocateUserBuffer(HANDLE hProcess,PVOID *BaseAddress,SIZE_T Size){
  SIZE_T Size1=Size;
  return ZwAllocateVirtualMemory(hProcess,BaseAddress,0L,(PULONG)&Size1,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
}

NTSTATUS DDKAPI MmFreeUserBuffer(HANDLE hProcess,PVOID *BaseAddress){
  ULONG RegionSize=0;
  return ZwFreeVirtualMemory(hProcess,BaseAddress,&RegionSize,MEM_RELEASE);
}

//set functions offsets...
BOOL DDKAPI SetOffsets(){
  BOOL bRet=TRUE;
  PsGetVersion(&winMajor,&winMinor,&winBuild,NULL);
  if(winMajor==6){
    switch(winMinor){
      case 0://Vista
        KiRetireDpcListSize=15;
        RtlCaptureContextSize=14;
      break;
      case 1://Win 7
        KiRetireDpcListSize=13;
        RtlCaptureContextSize=14;
      break;
      case 2://Win 8
      case 3://Win 8.1
      break;
      default:
        bRet=FALSE;
      break;
    }
  }
  return bRet;
}

VOID DDKAPI SetSeed(UINT s){
  rseed=s;
}

UINT DDKAPI Rand(){
  rseed=1103515245*rseed+12345;
  return ((rseed>>16)%0x8000);
}

VOID DDKAPI FakeSerialGenerator(VOID){
  LARGE_INTEGER sysTime;BYTE c,d;
  KeQuerySystemTime(&sysTime);
  SetSeed(sysTime.LowPart);
  for(c=0;c<5;c++)
    sserial[c]=' ';
  for(c=5;c<20;c++){
    if((c+1)%4)
      sserial[c]=(Rand()%0x1A)+0x41;
    else
      sserial[c]=(Rand()%0x0A)+0x30;
  }
  for(c=0,d=0;c<20;c++,d+=2){
    lserial[d]=Format[(sserial[c]>>4)&0xF];
    lserial[d+1]=Format[sserial[c]&0xF];
  }
}

//*********************************************************
// SYS HOOK Functions
//*********************************************************

NTSTATUS DDKAPI MyNtGdiBitBlt(HDC hDCDest,INT XDest,INT YDest,INT Width,
INT Height,HDC hDCSrc,INT XSrc,INT YSrc,DWORD ROP,IN DWORD crBackColor,IN FLONG fl){
  OBJECT_ATTRIBUTES oaAttributes={sizeof(OBJECT_ATTRIBUTES),0,0,0,0,0};
  NTSTATUS ret=STATUS_SUCCESS;PSSMSG pSSBuf=NULL;
  CLIENT_ID cidProcess;HANDLE hProcess;
  ExInterlockedIncrement(&nInHookRefCount);
  if(pSSBuffer&&pSSBuffer->uBuffSize&&CUSTOM_ROP!=ROP){
    cidProcess.UniqueProcess=PsGetCurrentProcessId();
    cidProcess.UniqueThread=0;
    if(NT_SUCCESS(ZwOpenProcess(&hProcess,PROCESS_ALL_ACCESS,&oaAttributes,&cidProcess))){
      MmAllocateUserBuffer(hProcess,(PVOID*)&pSSBuf,pSSBuffer->uBuffSize);
      if(pSSBuf){
        RtlCopyMemory(pSSBuf,pSSBuffer,pSSBuffer->uBuffSize);
        ret=pSecureNtGdiSetDIBitsToDeviceInternal(hDCDest,XDest,YDest,
        Width,Height,XSrc,YSrc,0,pSSBuf->bmi.bmiHeader.biHeight,pSSBuf->pBuffer,&pSSBuf->bmi,
        DIB_RGB_COLORS,pSSBuf->bmi.bmiHeader.biSizeImage,pSSBuf->bmi.bmiHeader.biSize,TRUE,NULL);
        MmFreeUserBuffer(hProcess,(PVOID*)&pSSBuf);
      }
      ZwClose(hProcess);
    }
  }else{
    if(CUSTOM_ROP==ROP){
      ROP=SRCCOPY;
    }
    ret=pSecureNtGdiBitBlt(hDCDest,XDest,YDest,Width,Height,hDCSrc,XSrc,YSrc,ROP,crBackColor,fl);
  }
  ExInterlockedDecrement(&nInHookRefCount);
  return ret;
}

//Earlier SpoofHDSerial
NTSTATUS DDKAPI MyNtDeviceIoControlFile(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,
  ULONG_PTR IoControlCode,PVOID InputBuffer,ULONG_PTR InputBufferLength,PVOID OutputBuffer,ULONG_PTR OutputBufferLength){
  PSTORAGE_DEVICE_DESCRIPTOR output;PSTORAGE_PROPERTY_QUERY input;PIDENTIFY_DEVICE_DATA hdid;PSERIALNUMBER shdid;
  PSENDCMDINPARAMS cmdinput;PSENDCMDOUTPARAMS cmdoutput;PSCSI_PASS_THROUGH sptin,sptout;

  // Call original...
  ExInterlockedIncrement(&nInHookRefCount);
  NTSTATUS result=pSecureNtDeviceIoControlFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,IoControlCode,InputBuffer,InputBufferLength,OutputBuffer,OutputBufferLength);

  if(!NT_SUCCESS(result)||(IoControlCode!=IOCTL_STORAGE_QUERY_PROPERTY&&IoControlCode!=SMART_RCV_DRIVE_DATA&&IoControlCode!=IOCTL_SCSI_PASS_THROUGH)){
    ExInterlockedDecrement(&nInHookRefCount);
    return result;
  }

  //need replase?
  if(OutputBuffer&&OutputBufferLength){
    switch(IoControlCode){
      case IOCTL_STORAGE_QUERY_PROPERTY:
        input=(PSTORAGE_PROPERTY_QUERY) InputBuffer;
        output=(PSTORAGE_DEVICE_DESCRIPTOR) OutputBuffer;
        if(input->PropertyId==StorageDeviceProperty&&input->QueryType==PropertyStandardQuery&&
          output->SerialNumberOffset&&OutputBufferLength>(output->SerialNumberOffset+39)){
          PCHAR serialnum=(PCHAR)output+output->SerialNumberOffset;
          memcpy(serialnum,lserial,40);
        }
      break;
      case SMART_RCV_DRIVE_DATA:
        cmdinput=(PSENDCMDINPARAMS) InputBuffer;
        cmdoutput=(PSENDCMDOUTPARAMS) OutputBuffer;
        if(cmdoutput->bBuffer&&(!cmdinput->irDriveRegs.bCommandReg||cmdinput->irDriveRegs.bCommandReg==ATA_IDENTIFY_DEVICE)){
          hdid=(PIDENTIFY_DEVICE_DATA)cmdoutput->bBuffer;
          memcpy(hdid->SerialNumber,sserial,20);
        }
      break;
      case IOCTL_SCSI_PASS_THROUGH:
        sptin=(PSCSI_PASS_THROUGH) InputBuffer;
        sptout=(PSCSI_PASS_THROUGH) OutputBuffer;
        if(sptin&&sptout&&sptin->Cdb[0]==SCSIOP_INQUIRY&&sptin->Cdb[1]==0x01&&sptin->Cdb[2]==0x80&&sptin->Cdb[4]>15){
          shdid=(PSERIALNUMBER)((PCHAR)sptout+sptout->DataBufferOffset);
          memcpy(shdid->SerialNumber,sserial,NSM_SERIAL_NUMBER_LENGTH);
        }
      break;
      default:break;
    }
  }
  ExInterlockedDecrement(&nInHookRefCount);
  return result;
}

// with some AV NtDeviceIoControlFile can take so long
// so use inline assembly
// First 4 parameters – RCX, RDX, R8, R9. Others passed on stack.
// func1(int a<RCX>, int b<RDX>, int c<R8>, int d<R9>, int e);
// but stack has reserved space for this four parameters!!!
// sixth parameter
// x86 -> 6 x 4 = 0x18...
// x64 -> 6 x 8 = 0x30...
INT DDKAPI MyNtDeviceIoControlFileAsm();
asm(
  ".text;\r\n"
  ".globl MyNtDeviceIoControlFileAsm\r\n"
  "MyNtDeviceIoControlFileAsm:\r\n"
  " mov 0x30(%rsp),%eax;\r\n"
  " cmp $0x2D1400,%eax;\r\n"
  " jz  MyNtDeviceIoControlFile;\r\n"
  " cmp $0x7C088,%eax;\r\n"
  " jz  MyNtDeviceIoControlFile;\r\n"
  " cmp $0x4D004,%eax;\r\n"
  " jz  MyNtDeviceIoControlFile;\r\n"
  " jmp *pSecureNtDeviceIoControlFile(%rip)"
);

NTSTATUS DDKAPI MyNtQueryVirtualMemory(HANDLE ProcessHandle,PVOID BaseAddress,MEMORY_INFORMATION_CLASS MemoryInformationClass,
  PVOID MemoryInformation,ULONG_PTR MemoryInformationLength,PULONG_PTR ReturnLength){
  // Call original...
  ExInterlockedIncrement(&nInHookRefCount);
  NTSTATUS result=pSecureNtQueryVirtualMemory(ProcessHandle,BaseAddress,MemoryInformationClass,
    MemoryInformation,MemoryInformationLength,ReturnLength);
  if(!NT_SUCCESS(result)||!RevBaseAddress||!RevRegionSize||
     (MemoryInformationClass!=MemoryBasicInformation&&MemoryInformationClass!=MemorySectionName)){
    ExInterlockedDecrement(&nInHookRefCount);
    return result;
  }

  //is our memory?
  if(BaseAddress>=RevBaseAddress&&BaseAddress<(PVOID)((LONG64)RevBaseAddress+RevRegionSize)){
    if(MemoryInformationClass==MemoryBasicInformation){
      PMEMORY_BASIC_INFORMATION_EX pMem=(PMEMORY_BASIC_INFORMATION_EX)MemoryInformation;
      //clear info ;)
      pMem->BaseAddress=RevBaseAddress;
      pMem->AllocationBase=NULL;
      pMem->AllocationProtect=0;
      pMem->RegionSize=RevRegionSize;
      pMem->Type=0;
      pMem->State=MEM_FREE;
      pMem->Protect=PAGE_NOACCESS;
    }
    if(MemoryInformationClass==MemorySectionName){
      //nothing here ;)
      result=STATUS_SECTION_NOT_IMAGE;
    }
  }

  ExInterlockedDecrement(&nInHookRefCount);
  return result;
}

NTSTATUS DDKAPI MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,ULONG_PTR SystemInformationLength,PULONG_PTR ReturnLength){
  PSYSTEM_PROCESSES_INFORMATION pSysProcInfo,pLastSysProcInfo;CHAR sFileName[MAX_PATH];
  ANSI_STRING DestinationString={MAX_PATH-sizeof(ANSI_NULL),MAX_PATH,sFileName};

  // Call original...
  ExInterlockedIncrement(&nInHookRefCount);
  NTSTATUS result=pSecureNtQuerySystemInformation(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);
  if(!NT_SUCCESS(result)||SystemInformationClass!=SystemProcessesAndThreadsInformation){
    ExInterlockedDecrement(&nInHookRefCount);
    return result;
  }

  // We Need Short Name...
  PCHAR sMeShortName=NULL,p="";
  while(*p)if(*(p++)=='\\')sMeShortName=p;
  if(!sMeShortName){
    ExInterlockedDecrement(&nInHookRefCount);
    return result;
  }

  // Start Find Me!
  pSysProcInfo=(PSYSTEM_PROCESSES_INFORMATION)SystemInformation;
  pLastSysProcInfo=NULL;
  while(pSysProcInfo){
    if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&DestinationString,&pSysProcInfo->ProcessName,FALSE))){
      DestinationString.Buffer[DestinationString.Length]=0;
      if(!strcmp(sMeShortName,sFileName)){
        // Hide Process
        if(pLastSysProcInfo){
          if(pSysProcInfo->NextEntryDelta)
            pLastSysProcInfo->NextEntryDelta+=pSysProcInfo->NextEntryDelta;
          else
            pLastSysProcInfo->NextEntryDelta=0;
        }else{
          if(pSysProcInfo->NextEntryDelta)
            SystemInformation+=pSysProcInfo->NextEntryDelta;
          else
            SystemInformation=NULL;
        }
        // Hide Threads
        pSysProcInfo->Threads[0].State=0;
        pSysProcInfo->ThreadCount=0;
      }
    }
    // This is the last? then exit...
    if(!pSysProcInfo->NextEntryDelta)
      break;
    // Save last and update!
    pLastSysProcInfo=pSysProcInfo;
    pSysProcInfo=(PSYSTEM_PROCESSES_INFORMATION)((PBYTE)pSysProcInfo+pSysProcInfo->NextEntryDelta);
  }
  ExInterlockedDecrement(&nInHookRefCount);
  return result;
}

NTSTATUS DDKAPI MyNtQueryInformationThread(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass,
  PVOID ThreadInformation,ULONG_PTR ThreadInformationLength,PULONG_PTR ReturnLength){
  PWOW64_CONTEXT pContext=(PWOW64_CONTEXT)ThreadInformation;BOOL bNeedHide=TRUE;
  static HANDLE ThreadId=0;
  ExInterlockedIncrement(&nInHookRefCount);

  // Custom message!
  if(ThreadInformationClass==ThreadWow64Context&&pContext&&pContext->ContextFlags==CONTEXT_DEBUG_REGISTERS_EX){
    pContext->ContextFlags=CONTEXT_DEBUG_REGISTERS;
    bNeedHide=FALSE;
    ThreadId=GetThreadIdFromHandle(ThreadHandle);
  }

  // Call original...
  NTSTATUS result=pSecureNtQueryInformationThread(ThreadHandle,ThreadInformationClass,
    ThreadInformation,ThreadInformationLength,ReturnLength);
  if(!NT_SUCCESS(result)||!bNeedHide||ThreadInformationClass!=ThreadWow64Context||
    !pContext||!(pContext->ContextFlags&CONTEXT_DEBUG_REGISTERS)){
    ExInterlockedDecrement(&nInHookRefCount);
    return result;
  }

  //it's my thread?
  if(GetThreadIdFromHandle(ThreadHandle)==ThreadId){
    if(!pContext->Eip){
      pContext->Dr0=0;
      pContext->Dr1=0;
      pContext->Dr2=0;
      pContext->Dr3=0;
      pContext->Dr7=0;
      pContext->Dr6=0;
    }
  }

  ExInterlockedDecrement(&nInHookRefCount);
  return result;
}

struct _KiRetireDpcListPattern{
  CHAR pattern[32];
  INT len;
}KiRetireDpcListPattern[2]={
  {
    //  *******   Win Vista   *******
    //  48 89 5C 24 10  mov     [rsp+arg_8], rbx
    //  48 89 6C 24 18  mov     [rsp+arg_10], rbp
    //  48 89 74 24 20  mov     [rsp+arg_18], rsi
    //  57              push    rdi
    //  41 54           push    r12
    //  41 55           push    r13
    //  41 56           push    r14
    //  41 57           push    r15
    //  48 83 EC 40     sub     rsp, 40h
    //  80 41 20 01     add     byte ptr [rcx+20h], 1
    { 0x48,0x89,0x5C,0x24,0x10,0x48,0x89,0x6C,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x40,0x80,0x41,0x20,0x01 },
    32
  },
  {
    //  *******   Win 7   *******
    //  FF F3         push    rbx
    //  55            push    rbp
    //  56            push    rsi
    //  57            push    rdi
    //  41 54         push    r12
    //  41 55         push    r13
    //  41 56         push    r14
    //  41 57         push    r15
    //  48 83 EC 68   sub     rsp, 68h
    //  48 8B 71 08   mov     rsi, [rcx+8]
    { 0xFF,0xF3,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x68,0x48,0x8B,0x71,0x08 },
    21
  }
};

//jmp [address]
//0xXXXXXXXXXXXXXXXX - address
//BYTE hjumper2[ABS_JUMP_LEN2]={0xFF,0x25,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

//mov rax, 0xXXXXXXXXXXXXXXXX
//jmp rax
BYTE hjumper[ABS_JUMP_LEN]={0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xe0};//rax

BOOL DDKAPI InitializeHooksData(){
  static BOOL bRet=FALSE;
  /*if(winMajor>5&&!(KdDebuggerEnabled&1)){//patchguard...
    return FALSE;
  }*/
  if(!bRet){
    memset(&kHooks,0,sizeof(kHooks));
    PSYSTEM_MODULE_INFORMATION_64 pSMInfo=GetSystemModuleInformation();
    if(pSMInfo){
      kHooks.ntoskrnl.Base=GetModuleBaseAddressAndSize(pSMInfo,NULL,&kHooks.ntoskrnl.Size,NULL);
      if(kHooks.ntoskrnl.Base&&kHooks.ntoskrnl.Size){//&&MmIsAddressValid(kHooks.ntoskrnl.Base)){
        ULONGLONG tbl_address=FindCodeAddress((ULONGLONG)kHooks.ntoskrnl.Base,(ULONGLONG)kHooks.ntoskrnl.Base+kHooks.ntoskrnl.Size,
          (PBYTE)"\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00\x4C\x8D",15,15,TRUE);
        if(tbl_address){
          ULONG i;
          for(i=0;i<50;i++){
            ULONGLONG p=tbl_address+i;
            if(*(USHORT*)p==(USHORT)0x8d4c){
              kHooks.ServiceDescriptorShadowTable=(PSERVICE_DESCRIPTOR_TABLE)((p+7)+*(LONG*)(p+3));
              break;
            }
          }
        }
        if(kHooks.ServiceDescriptorShadowTable){
          kHooks.ntoskrnl.pSST=kHooks.ServiceDescriptorShadowTable->ntoskrnl.ServiceTable;
          kHooks.ntoskrnl.Space=(PBYTE)FindFreeExecSpace(kHooks.ntoskrnl.Base,HOOK_ALIGMENT*(MAX_HOOK_NUMBER+1));
          if(kHooks.ntoskrnl.Space){
            if((ULONGLONG)kHooks.ntoskrnl.Space%HOOK_ALIGMENT)
              kHooks.ntoskrnl.Space+=HOOK_ALIGMENT-(ULONGLONG)kHooks.ntoskrnl.Space%HOOK_ALIGMENT;
            kHooks.win32k.Base=GetModuleBaseAddressAndSize(pSMInfo,(PVOID)kHooks.ServiceDescriptorShadowTable->win32k.ServiceTable,&kHooks.win32k.Size,NULL);
            if(kHooks.win32k.Base&&kHooks.win32k.Size){//&&MmIsAddressValid(kHooks.win32k.Base)){
              kHooks.win32k.pSST=kHooks.ServiceDescriptorShadowTable->win32k.ServiceTable;
              kHooks.win32k.Space=(PBYTE)FindFreeExecSpace(kHooks.win32k.Base,HOOK_ALIGMENT*(MAX_HOOK_NUMBER+1));
              if(kHooks.win32k.Space){
                if((ULONGLONG)kHooks.win32k.Space%HOOK_ALIGMENT)
                  kHooks.win32k.Space+=HOOK_ALIGMENT-(ULONGLONG)kHooks.win32k.Space%HOOK_ALIGMENT;
                bRet=TRUE;
              }
            }
          }
        }
        //get KiRetireDpcList Address
        if(winMajor==6&&winMinor<2){
          kHooks.KiRetireDpcListAddress=FindCodeAddress((ULONGLONG)kHooks.ntoskrnl.Base,(ULONGLONG)kHooks.ntoskrnl.Base+kHooks.ntoskrnl.Size,
            (PBYTE)KiRetireDpcListPattern[winMinor].pattern,KiRetireDpcListPattern[winMinor].len,0,TRUE);
        }
      }
      ExFreePoolWithTag(pSMInfo,0);
    }
  }
  return bRet;
}

PVOID DDKAPI HookSYSFunction(PKERNELMODULEHOOKS pMod,BYTE hNumber,DWORD funcOffset,PVOID newDirApi,PVOID* pPointer){
  PVOID NtAPIAddress=NULL;PVOID pAPIFunc=NULL;
  ULONGLONG accessmask=0;DWORD RelOffset=0;PBYTE JmpOffset=NULL;

  if(!pMod||hNumber>=MAX_HOOK_NUMBER||!funcOffset||!newDirApi||!pPointer){
    return NULL;
  }

  NtAPIAddress=&pMod->pSST[funcOffset/2];
  pAPIFunc=DecodeSSDTAddress(pMod->pSST,NtAPIAddress,funcOffset%2);
  JmpOffset=(PBYTE)(pMod->Space+HOOK_ALIGMENT*hNumber);
  RelOffset=EncodeSSDTAddress(pMod->pSST,NtAPIAddress,JmpOffset,funcOffset%2);

  if(!RelOffset||!pAPIFunc||!pMod->Space||pMod->Hook[hNumber].JmpBuffer){//already used...
    return NULL;
  }

  //save information data...
  pMod->Hook[hNumber].FuncOffset=funcOffset;
  pMod->Hook[hNumber].NtAPIAddress=(PULARGE_INTEGER)MmMapAddress(NtAPIAddress,sizeof(PVOID));
  pMod->Hook[hNumber].JmpBuffer=(PBYTE)MmMapAddress(JmpOffset,HOOK_ALIGMENT);

  //redirect...
  *pPointer=pAPIFunc;

  asm(
    "cli;\r\n"
    "movq %%cr0,%%rax;\r\n"
    "movq %%rax,%0;\r\n"
    "and $~(1<<16),%%rax;\r\n"
    "movq %%rax,%%cr0":"=m"(accessmask)::"%rax"
  );

  //save original content...
  memmove(pMod->Hook[hNumber].OrigContent,pMod->Hook[hNumber].JmpBuffer,HOOK_ALIGMENT);
  //set relocation table jump...
  memmove(hjumper+2,&newDirApi,sizeof(PVOID));
  memmove(pMod->Hook[hNumber].JmpBuffer,hjumper,ABS_JUMP_LEN);

  //change func offset...
  if(funcOffset%2){
    pMod->Hook[hNumber].RealOffset=pMod->Hook[hNumber].NtAPIAddress->HighPart;
    pMod->Hook[hNumber].NtAPIAddress->HighPart=RelOffset;
  }else{
    pMod->Hook[hNumber].RealOffset=pMod->Hook[hNumber].NtAPIAddress->LowPart;
    pMod->Hook[hNumber].NtAPIAddress->LowPart=RelOffset;
  }

  asm(
    "movq %0,%%rax;\r\n"
    "movq %%rax,%%cr0;\r\n"
    "sti"::"m"(accessmask):"%rax"
  );

  return NtAPIAddress;
}

BOOL DDKAPI UnHookSYSFunction(PKERNELMODULEHOOKS pMod,BYTE hNumber){
  ULONGLONG accessmask=0;
  if(hNumber>=MAX_HOOK_NUMBER||!pMod->Hook[hNumber].NtAPIAddress||!pMod->Hook[hNumber].RealOffset){//not used...
    return FALSE;
  }

  asm(
    "cli;\r\n"
    "movq %%cr0,%%rax;\r\n"
    "movq %%rax,%0;\r\n"
    "and $~(1<<16),%%rax;\r\n"
    "movq %%rax,%%cr0":"=m"(accessmask)::"%rax"
  );

  //change func offset...
  if(pMod->Hook[hNumber].FuncOffset%2)
    pMod->Hook[hNumber].NtAPIAddress->HighPart=pMod->Hook[hNumber].RealOffset;
  else
    pMod->Hook[hNumber].NtAPIAddress->LowPart=pMod->Hook[hNumber].RealOffset;

  asm(
    "movq %0,%%rax;\r\n"
    "movq %%rax,%%cr0;\r\n"
    "sti"::"m"(accessmask):"%rax"
  );

  MmUnmapIoSpace(pMod->Hook[hNumber].NtAPIAddress,sizeof(PVOID));

  return TRUE;
}

VOID DDKAPI ClearBuffers(){

  ULONGLONG accessmask=0;BYTE i;
  PKERNELMODULEHOOKS pMod;

  asm(
    "cli;\r\n"
    "movq %%cr0,%%rax;\r\n"
    "movq %%rax,%0;\r\n"
    "and $~(1<<16),%%rax;\r\n"
    "movq %%rax,%%cr0":"=m"(accessmask)::"%rax"
  );

  pMod=&kHooks.ntoskrnl;
  for(i=0;i<MAX_HOOK_NUMBER;i++){
    if(pMod->Hook[i].JmpBuffer){
      //restore original content...
      memmove(pMod->Hook[i].JmpBuffer,pMod->Hook[i].OrigContent,HOOK_ALIGMENT);
      memset(pMod->Hook[i].OrigContent,0x00,HOOK_ALIGMENT);
      MmUnmapIoSpace(pMod->Hook[i].JmpBuffer,HOOK_ALIGMENT);
      //reset vars...
      pMod->Hook[i].JmpBuffer=NULL;
      pMod->Hook[i].NtAPIAddress=NULL;
      pMod->Hook[i].RealOffset=0;
      pMod->Hook[i].FuncOffset=0;
    }
  }
  pMod=&kHooks.win32k;
  for(i=0;i<MAX_HOOK_NUMBER;i++){
    if(pMod->Hook[i].JmpBuffer){
      //restore original content...
      memmove(pMod->Hook[i].JmpBuffer,pMod->Hook[i].OrigContent,HOOK_ALIGMENT);
      memset(pMod->Hook[i].OrigContent,0x00,HOOK_ALIGMENT);
      MmUnmapIoSpace(pMod->Hook[i].JmpBuffer,HOOK_ALIGMENT);
      //reset vars...
      pMod->Hook[i].JmpBuffer=NULL;
      pMod->Hook[i].NtAPIAddress=NULL;
      pMod->Hook[i].RealOffset=0;
      pMod->Hook[i].FuncOffset=0;
    }
  }

  asm(
    "movq %0,%%rax;\r\n"
    "movq %%rax,%%cr0;\r\n"
    "sti"::"m"(accessmask):"%rax"
  );
}

PVOID DDKAPI HookFunction(PVOID pAPIFunc,PVOID newDirApi,DWORD nBytes,PVOID* pPointer){
  DWORD accessmask=0;
  if(!pAPIFunc||!newDirApi||nBytes<ABS_JUMP_LEN||!pPointer){//already used...
    return NULL;
  }

  //allocate buffer...
  PBYTE pBuffer=(PBYTE)ExAllocatePoolWithTag(NonPagedPool,nBytes+ABS_JUMP_LEN,0);
  if(!pBuffer){
    return NULL;
  }

  //save original content...
  PVOID newAddress=pAPIFunc+nBytes;
  memmove(pBuffer,pAPIFunc,nBytes);
  memmove(hjumper+2,&newAddress,sizeof(PVOID));
  memmove(pBuffer+nBytes,hjumper,ABS_JUMP_LEN);
  //secure pointer
  *pPointer=pBuffer;

  asm(
    "cli;\r\n"
    "movq %%cr0,%%rax;\r\n"
    "movq %%rax,%0;\r\n"
    "and $~(1<<16),%%rax;\r\n"
    "movq %%rax,%%cr0":"=m"(accessmask)::"%rax"
  );

  //set relocation table jump...
  memmove(hjumper+2,&newDirApi,sizeof(PVOID));
  memmove(pAPIFunc,hjumper,ABS_JUMP_LEN);

  asm(
    "movq %0,%%rax;\r\n"
    "movq %%rax,%%cr0;\r\n"
    "sti"::"m"(accessmask):"%rax"
  );

  return pBuffer;
}

BOOL DDKAPI UnHookFunction(PVOID pAPIFunc,PVOID pBuffer){
  DWORD accessmask=0;
  if(!pAPIFunc||!pBuffer){
    return FALSE;
  }

  asm(
    "cli;\r\n"
    "movq %%cr0,%%rax;\r\n"
    "movq %%rax,%0;\r\n"
    "and $~(1<<16),%%rax;\r\n"
    "movq %%rax,%%cr0":"=m"(accessmask)::"%rax"
  );

  memmove(pAPIFunc,pBuffer,ABS_JUMP_LEN);

  asm(
    "movq %0,%%rax;\r\n"
    "movq %%rax,%%cr0;\r\n"
    "sti"::"m"(accessmask):"%rax"
  );

  ExFreePoolWithTag(pBuffer,0);
  return TRUE;
}

//*********************************************************
// HOOK Functions
//*********************************************************

KDPC g_TempDpc[0x100];
PVOID g_CpuContextAddress=NULL;
ULONG g_ThreadContextRoutineOffset = 0;
UINT g_MaxCpu=0;

VOID AdjustStackCallPointer(ULONG_PTR NewStackPointer,PVOID StartAddress,PVOID Argument);
asm(
  ".text;\r\n"
  ".globl AdjustStackCallPointer\r\n"
  "AdjustStackCallPointer:\r\n"
  " mov %rcx,%rsp;\r\n"
  " xchg %rcx,%r8;\r\n"
  " jmp *%rdx"
);

CHAR GetCpuIndex();
asm(
  ".text;\r\n"
  ".globl GetCpuIndex\r\n"
  "GetCpuIndex:\r\n"
  " mov     %gs:0x52,%al;\r\n"
  " movzx   %al,%eax;\r\n"
  " ret"
);

VOID DDKAPI RestoreCpuContext();
asm(
  ".text;\r\n"
  ".globl RestoreCpuContext\r\n"
  "RestoreCpuContext:\r\n"
  " push    %rax;\r\n"
  " sub     $0x20,%rsp;\r\n"
  " call    GetCpuIndex;\r\n"
  " add     $0x20,%rsp;\r\n"
  " mov     $0x170,%r11;\r\n"
  " mul     %r11;\r\n"
  " mov     %rax,%r11;\r\n"
  " add     g_CpuContextAddress(%rip),%r11;\r\n"//R11 = g_CpuContext[CpuIndex]
  " pop     %rax;\r\n"
  " mov     0x48(%r11),%rsp;\r\n"
  " mov     0x40(%r11),%rbx;\r\n"
  " mov     %rbx,(%rsp);\r\n"
  " movdqa  0x50(%r11),%xmm0;\r\n"
  " movdqa  0x60(%r11),%xmm1;\r\n"
  " movdqa  0x70(%r11),%xmm2;\r\n"
  " movdqa  0x80(%r11),%xmm3;\r\n"
  " movdqa  0x90(%r11),%xmm4;\r\n"
  " movdqa  0xA0(%r11),%xmm5;\r\n"
  " movdqa  0xB0(%r11),%xmm6;\r\n"
  " movdqa  0xC0(%r11),%xmm7;\r\n"
  " movdqa  0xD0(%r11),%xmm8;\r\n"
  " movdqa  0xE0(%r11),%xmm9;\r\n"
  " movdqa  0xF0(%r11),%xmm10;\r\n"
  " movdqa  0x100(%r11),%xmm11;\r\n"
  " movdqa  0x110(%r11),%xmm12;\r\n"
  " movdqa  0x120(%r11),%xmm13;\r\n"
  " movdqa  0x130(%r11),%xmm14;\r\n"
  " movdqa  0x140(%r11),%xmm15;\r\n"
  " mov     (%r11),%rbx;\r\n"
  " mov     0x08(%r11),%rsi;\r\n"
  " mov     0x10(%r11),%rdi;\r\n"
  " mov     0x18(%r11),%rbp;\r\n"
  " mov     0x20(%r11),%r12;\r\n"
  " mov     0x28(%r11),%r13;\r\n"
  " mov     0x30(%r11),%r14;\r\n"
  " mov     0x38(%r11),%r15;\r\n"
  " mov     0x150(%r11),%rcx;\r\n"
  " mov     0x158(%r11),%rdx;\r\n"
  " mov     0x160(%r11),%r8;\r\n"
  " mov     0x168(%r11),%r9;\r\n"
  " ret"
);

VOID DDKAPI RestoreDpcContext();
asm(
  ".text;\r\n"
  ".globl RestoreDpcContext\r\n"
  "RestoreDpcContext:\r\n"
  " sub     $0x20,%rsp;\r\n"
  " call    GetCpuIndex;\r\n"
  " add     $0x20,%rsp;\r\n"
  " mov     $0x170,%r11;\r\n"
  " mul     %r11;\r\n"
  " mov     %rax,%r11;\r\n"
  " add     g_CpuContextAddress(%rip),%r11;\r\n"//R11 = g_CpuContext[CpuIndex]
  " mov     0x40(%r11),%rax;\r\n"
  " sub     $5,%rax;\r\n"//here directly RIP = RIP-5, which is returned to Call KiXX 5-byte instruction jmp RestoreCpuContext
  " mov     %rax,0x40(%r11);\r\n"
  " jmp     RestoreCpuContext"
);

// NULL Anti-Patchguard DPC
VOID PgTempDpc(struct _KDPC *Dpc,PVOID DeferredContext,PVOID SystemArgument1,PVOID SystemArgument2){
  return;
}

VOID OnRtlCaptureContext(PHOOK_CTX hookCtx){
  PCONTEXT pCtx = (PCONTEXT)(hookCtx->rcx);
  ULONG64 Rip = *(ULONG64 *)(hookCtx->rsp);
  ULONG64 Rcx = *(ULONG64 *)(hookCtx->rsp+0x48);

  // Call original...
  ExInterlockedIncrement(&nInHookRefCount);
  pSecureRtlCaptureContext(pCtx);

  pCtx->Rsp = hookCtx->rsp+0x08;
  pCtx->Rip = Rip;
  pCtx->Rax = hookCtx->rax;
  pCtx->Rbx = hookCtx->rbx;
  pCtx->Rcx = hookCtx->rcx;
  pCtx->Rdx = hookCtx->rdx;
  pCtx->Rsi = hookCtx->rsi;
  pCtx->Rdi = hookCtx->rdi;
  pCtx->Rbp = hookCtx->rbp;
  pCtx->R8  = hookCtx->r8;
  pCtx->R9  = hookCtx->r9;
  pCtx->R10 = hookCtx->r10;
  pCtx->R11 = hookCtx->r11;
  pCtx->R12 = hookCtx->r12;
  pCtx->R13 = hookCtx->r13;
  pCtx->R14 = hookCtx->r14;
  pCtx->R15 = hookCtx->r15;

  if(Rip>=(ULONG64)KeBugCheckExOrig && Rip<=(ULONG64)KeBugCheckExOrig+0x64 && Rcx==0x109){
    // Get original thread start address from ETHREAD
    PCHAR CurrentThread=(PCHAR)PsGetCurrentThread();
    PVOID StartRoutine=*(PVOID **)(CurrentThread + g_ThreadContextRoutineOffset);

    // Get Initial stack pointer
    PVOID StackPointer=IoGetInitialStack();
    CHAR  Cpu=GetCpuIndex();

    // Initialize and queue Anti Patchguard Dpc
    KeInitializeDpc(&g_TempDpc[(int)Cpu],PgTempDpc,NULL);
    KeSetTargetProcessorDpc(&g_TempDpc[(int)Cpu],(CCHAR)Cpu);
    KeInsertQueueDpc(&g_TempDpc[(int)Cpu],NULL,NULL);

    // If target Os is Windows 7
    if(winMajor>=6&&winMinor>=1)
      // Put stack base address in first stack element
      *(ULONG64 *)StackPointer=(((ULONG_PTR)StackPointer+0x1000) & (~0xFFF));
    if(KeGetCurrentIrql()>PASSIVE_LEVEL){
      ExInterlockedDecrement(&nInHookRefCount);
      // Restore original DPC context ("KiRetireDpcList" interrupt plays
      // a key role here).  This call doesn't return
      RestoreDpcContext();
    }else{
      ExInterlockedDecrement(&nInHookRefCount);
      // Jump directly to original thread start address (ExpWorkerThread)
      AdjustStackCallPointer((ULONG_PTR)StackPointer - 0x8,StartRoutine,NULL);
    }
  }else{
    ExInterlockedDecrement(&nInHookRefCount);
  }
}

VOID HookKiRetireDpcList(VOID);
asm(
  ".text;\r\n"
  ".globl HookKiRetireDpcList\r\n"
  "HookKiRetireDpcList:\r\n"
  " push    %rcx;\r\n"
  " push    %rdx;\r\n"
  " push    %r8;\r\n"
  " push    %r9;\r\n"
  " sub     $0x20,%rsp;\r\n"
  " call    GetCpuIndex;\r\n"
  " add     $0x20,%rsp;\r\n"
  " pop     %r9;\r\n"
  " pop     %r8;\r\n"
  " pop     %rdx;\r\n"
  " pop     %rcx;\r\n"
  " mov     $0x170,%r11;\r\n"
  " mul     %r11;\r\n"
  " add     g_CpuContextAddress(%rip),%rax;\r\n"//RAX = g_CpuContext[CpuIndex]
  " mov     %rbx,(%rax);\r\n"
  " mov     %rsi,0x8(%rax);\r\n"
  " mov     %rdi,0x10(%rax);\r\n"
  " mov     %rbp,0x18(%rax);\r\n"
  " mov     %r12,0x20(%rax);\r\n"
  " mov     %r13,0x28(%rax);\r\n"
  " mov     %r14,0x30(%rax);\r\n"
  " mov     %r15,0x38(%rax);\r\n"
  " movdqa  %xmm0,0x50(%rax);\r\n"
  " movdqa  %xmm1,0x60(%rax);\r\n"
  " movdqa  %xmm2,0x70(%rax);\r\n"
  " movdqa  %xmm3,0x80(%rax);\r\n"
  " movdqa  %xmm4,0x90(%rax);\r\n"
  " movdqa  %xmm5,0xA0(%rax);\r\n"
  " movdqa  %xmm6,0xB0(%rax);\r\n"
  " movdqa  %xmm7,0xC0(%rax);\r\n"
  " movdqa  %xmm8,0xD0(%rax);\r\n"
  " movdqa  %xmm9,0xE0(%rax);\r\n"
  " movdqa  %xmm10,0xF0(%rax);\r\n"
  " movdqa  %xmm11,0x100(%rax);\r\n"
  " movdqa  %xmm12,0x110(%rax);\r\n"
  " movdqa  %xmm13,0x120(%rax);\r\n"
  " movdqa  %xmm14,0x130(%rax);\r\n"
  " movdqa  %xmm15,0x140(%rax);\r\n"
  " mov     %rcx,0x150(%rax);\r\n"
  " mov     %rdx,0x158(%rax);\r\n"
  " mov     %r8,0x160(%rax);\r\n"
  " mov     %r9,0x168(%rax);\r\n"
  " mov     (%rsp),%r11;\r\n"
  " mov     %r11,0x40(%rax);\r\n"
  " mov     %rsp,%r11;\r\n"
  " mov     %r11,0x48(%rax);\r\n"
  " lea     RestoreCpuContext(%rip),%rax;\r\n"
  " mov   %rax,(%rsp);\r\n"
  " jmp   *pSecureKiRetireDpcList(%rip)"
);

VOID HookRtlCaptureContext(VOID);
asm(
  ".text;\r\n"
  ".globl HookRtlCaptureContext\r\n"
  "HookRtlCaptureContext:\r\n"
  " push %rsp;\r\n"
  " pushfq;\r\n"
  " push %r15;\r\n"
  " push %r14;\r\n"
  " push %r13;\r\n"
  " push %r12;\r\n"
  " push %r11;\r\n"
  " push %r10;\r\n"
  " push %r9;\r\n"
  " push %r8;\r\n"
  " push %rdi;\r\n"
  " push %rsi;\r\n"
  " push %rbp;\r\n"
  " push %rbx;\r\n"
  " push %rdx;\r\n"
  " push %rcx;\r\n"
  " push %rax;\r\n"
  " mov %rsp,%rcx;\r\n"
  " sub $0x28,%rsp;\r\n"
  " call OnRtlCaptureContext;\r\n"
  " add $0x28,%rsp;\r\n"
  " pop %rax;\r\n"
  " pop %rcx;\r\n"
  " pop %rdx;\r\n"
  " pop %rbx;\r\n"
  " pop %rbp;\r\n"
  " pop %rsi;\r\n"
  " pop %rdi;\r\n"
  " pop %r8;\r\n"
  " pop %r9;\r\n"
  " pop %r10;\r\n"
  " pop %r11;\r\n"
  " pop %r12;\r\n"
  " pop %r13;\r\n"
  " pop %r14;\r\n"
  " pop %r15;\r\n"
  " popfq;\r\n"
  " pop %rsp;\r\n"
  " ret"
);

VOID DisablePatchProtectionSystemThreadRoutine(PVOID Nothing){
  UNICODE_STRING Symbol;
  if(!kHooks.KiRetireDpcListAddress){
    return;
  }
  PUCHAR CurrentThread=(PUCHAR)PsGetCurrentThread();
  for(g_ThreadContextRoutineOffset=0;g_ThreadContextRoutineOffset<0x1000;g_ThreadContextRoutineOffset+=4){
    if(*(PVOID **)(CurrentThread+g_ThreadContextRoutineOffset)==(PVOID)DisablePatchProtectionSystemThreadRoutine)
      break;
  }
  if(g_ThreadContextRoutineOffset<0x1000){
    g_MaxCpu=(UINT)KeNumberProcessors;
    g_CpuContextAddress=(PVOID)ExAllocatePool(NonPagedPool,0x200*g_MaxCpu+0x1000);
    if(!g_CpuContextAddress){
      return;
    }
    RtlZeroMemory(g_TempDpc,sizeof(KDPC)*0x100);
    RtlZeroMemory(g_CpuContextAddress,0x200*g_MaxCpu);
    //KeBugCheckEx
    RtlInitUnicodeString(&Symbol,L"KeBugCheckEx");
    KeBugCheckExOrig=(PVOID *)MmGetSystemRoutineAddress(&Symbol);
    if(KeBugCheckExOrig){
      //Hook KiRetireDpcList
      KiRetireDpcListOrig=(PVOID)kHooks.KiRetireDpcListAddress;
      pKiRetireDpcList=(tKiRetireDpcList)HookFunction(KiRetireDpcListOrig,HookKiRetireDpcList,KiRetireDpcListSize,(PVOID*)&pSecureKiRetireDpcList);
      if(pKiRetireDpcList){
        //Hook RtlCaptureContext
        RtlInitUnicodeString(&Symbol,L"RtlCaptureContext");
        RtlCaptureContextOrig=(PVOID *)MmGetSystemRoutineAddress(&Symbol);
        pRtlCaptureContext=(tRtlCaptureContext)HookFunction(RtlCaptureContextOrig,HookRtlCaptureContext,RtlCaptureContextSize,(PVOID*)&pSecureRtlCaptureContext);
      }
    }
  }
}

NTSTATUS DisablePatchProtection(){
  OBJECT_ATTRIBUTES Attributes;
  NTSTATUS Status;HANDLE ThreadHandle=NULL;
  InitializeObjectAttributes(&Attributes,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
  Status=PsCreateSystemThread(&ThreadHandle,THREAD_ALL_ACCESS,&Attributes,NULL,
    NULL,DisablePatchProtectionSystemThreadRoutine,NULL);
  if(ThreadHandle)
    ZwClose(ThreadHandle);
  return Status;
}

//*********************************************************
// Patchguard Functions
//*********************************************************

VOID DDKAPI NotifyRoutine(HANDLE ParentId,HANDLE ProcessId,BOOLEAN bCreate){
  PEPROCESS PEPObject=NULL;CHAR sProcessName[MAX_PATH]={0};
  if(bDriverInit){
    if(NT_SUCCESS(PsLookupProcessByProcessId(ProcessId,&PEPObject))){
      if(ImageFileName(PEPObject,sProcessName)){
        if(bCreate){
        }else{
        }
      }
      ObDereferenceObject(PEPObject);
    }
  }
}

VOID DDKAPI ForceRestoreSystem(){
  LARGE_INTEGER Interval;
  if(bDriverInit&&InitializeHooksData()){
    //UNHOOK NtDeviceIoControlFile
    if(pNtDeviceIoControlFile){
      UnHookSYSFunction(&kHooks.ntoskrnl,0);
      pNtDeviceIoControlFile=NULL;
    }
    //UNHOOK NtQuerySystemInformation
    if(pNtQuerySystemInformation){
      UnHookSYSFunction(&kHooks.ntoskrnl,1);
      pNtQuerySystemInformation=NULL;
    }
    //UNHOOK NtQueryInformationThread
    if(pNtQueryInformationThread){
      UnHookSYSFunction(&kHooks.ntoskrnl,2);
      pNtQueryInformationThread=NULL;
    }
    //UNHOOK NtQueryVirtualMemory
    if(pNtQueryVirtualMemory){
      UnHookSYSFunction(&kHooks.ntoskrnl,3);
      pNtQueryVirtualMemory=NULL;
    }
    //UNHOOK NtGdiBitBlt
    if(pNtGdiBitBlt){
      UnHookSYSFunction(&kHooks.win32k,0);
      pNtGdiBitBlt=NULL;
    }
    //FREE NtGdiSetDIBitsToDevice
    if(pNtGdiSetDIBitsToDeviceInternal){
      pNtGdiSetDIBitsToDeviceInternal=NULL;
    }
    //UNHOOK KiRetireDpcList
    if(pKiRetireDpcList){
      UnHookFunction(KiRetireDpcListOrig,pKiRetireDpcList);
      pKiRetireDpcList=NULL;
    }
    //UNHOOK RtlCaptureContext
    if(pRtlCaptureContext){
      UnHookFunction(RtlCaptureContextOrig,pRtlCaptureContext);
      pRtlCaptureContext=NULL;
    }
    //FREE Hooks Buffers...
    do{
      Interval.QuadPart=WDF_REL_TIMEOUT_IN_MS(10);
      KeDelayExecutionThread(KernelMode,FALSE,&Interval);
    }while(nInHookRefCount.QuadPart);
    //clear buffers
    ClearBuffers();
  }
  //Free memory
  if(pSSBuffer){
    ExFreePoolWithTag(pSSBuffer,0);
    pSSBuffer=NULL;
  }
  //Free context memory
  if(g_CpuContextAddress){
    ExFreePool(g_CpuContextAddress);
    g_CpuContextAddress=NULL;
  }
  if(bDriverInit)
    bDriverInit=FALSE;
}

//DRIVER IOCTL CODES!
#define IOCTL_DRIVER_INIT     CTL_CODE(0,502,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_DRIVER_END      CTL_CODE(0,502,METHOD_NEITHER,FILE_ANY_ACCESS)
#define IOCTL_DRIVER_BMPBUF   CTL_CODE(0,503,METHOD_IN_DIRECT,FILE_ANY_ACCESS)

NTSTATUS DDKAPI DeviceControl(PDEVICE_OBJECT DeviceObject,PIRP Irp){
  PSSMSG pSSMsg=NULL;PDRIVERMSG pDriverMsg=NULL;
  PIO_STACK_LOCATION pIoStackIrp=IoGetCurrentIrpStackLocation(Irp);
  NTSTATUS ntStatus=STATUS_SUCCESS;
  if(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode==IOCTL_DRIVER_INIT){
    pDriverMsg=(PDRIVERMSG)(Irp->AssociatedIrp.SystemBuffer);
    if(!bDriverInit&&SetOffsets()&&InitializeHooksData()){

      //need to patch?
      if(RtlCaptureContextSize&&KiRetireDpcListSize){
        DisablePatchProtection();
      }

      //New way to get Table...
      PSERVICE_DESCRIPTOR_TABLE pServiceDescriptorShadowTable=kHooks.ServiceDescriptorShadowTable;

      //HOOK NtDeviceIoControlFile
      NtDeviceIoControlFileOffset=pDriverMsg->NtDICFOffset;
      NtDeviceIoControlFileAddress=HookSYSFunction(&kHooks.ntoskrnl,0,NtDeviceIoControlFileOffset,(PBYTE)MyNtDeviceIoControlFileAsm,(PVOID*)&pSecureNtDeviceIoControlFile);
      pNtDeviceIoControlFile=pSecureNtDeviceIoControlFile;

      //HOOK NtQuerySystemInformation
      NtQuerySystemInformationOffset=pDriverMsg->NtQSIOffset;
      NtDeviceIoControlFileAddress=HookSYSFunction(&kHooks.ntoskrnl,1,NtQuerySystemInformationOffset,(PBYTE)MyNtQuerySystemInformation,(PVOID*)&pSecureNtQuerySystemInformation);
      pNtQuerySystemInformation=pSecureNtQuerySystemInformation;

      //HOOK NtQueryInformationThread
      NtQueryInformationThreadOffset=pDriverMsg->NtQITOffset;
      NtQueryInformationThreadAddress=HookSYSFunction(&kHooks.ntoskrnl,2,NtQueryInformationThreadOffset,(PBYTE)MyNtQueryInformationThread,(PVOID*)&pSecureNtQueryInformationThread);
      pNtQueryInformationThread=pSecureNtQueryInformationThread;

      //HOOK NtQueryVirtualMemory
      NtQueryVirtualMemoryOffset=pDriverMsg->NtQVMOffset;
      NtQueryVirtualMemoryAddress=HookSYSFunction(&kHooks.ntoskrnl,3,NtQueryVirtualMemoryOffset,(PBYTE)MyNtQueryVirtualMemory,(PVOID*)&pSecureNtQueryVirtualMemory);
      pNtQueryVirtualMemory=pSecureNtQueryVirtualMemory;

      //HOOK GDI
      //HOOK NtGdiBitBlt
      NtGdiBitBltOffset=pDriverMsg->NtGBBOffset-0x1000;
      NtGdiBitBltAddress=HookSYSFunction(&kHooks.win32k,0,NtGdiBitBltOffset,(PBYTE)MyNtGdiBitBlt,(PVOID*)&pSecureNtGdiBitBlt);
      pNtGdiBitBlt=pSecureNtGdiBitBlt;

      //NtGdiSetDIBitsToDeviceInternal
      NtGdiSetDIBitsToDeviceInternalOffset=pDriverMsg->NtGSDIBTDIOffset-0x1000;
      NtGdiSetDIBitsToDeviceInternalAddress=(PVOID*)&pServiceDescriptorShadowTable->win32k.ServiceTable[NtGdiSetDIBitsToDeviceInternalOffset/2];
      pNtGdiSetDIBitsToDeviceInternal=(tNtGdiSetDIBitsToDeviceInternal)DecodeSSDTAddress(pServiceDescriptorShadowTable->win32k.ServiceTable,NtGdiSetDIBitsToDeviceInternalAddress,NtGdiSetDIBitsToDeviceInternalOffset%2);
      pSecureNtGdiSetDIBitsToDeviceInternal=pNtGdiSetDIBitsToDeviceInternal;

      bDriverInit=TRUE;
    }
  }

  if(bDriverInit){

    switch(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode){
      case IOCTL_DRIVER_BMPBUF:
        if(pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength){
          pSSMsg=(PSSMSG)(MmGetSystemAddressForMdlSafe(Irp->MdlAddress,NormalPagePriority));
          if(pSSMsg){
            if(!pSSBuffer)
              pSSBuffer=(PSSMSG)ExAllocatePoolWithTag(NonPagedPool,pSSMsg->uBuffSize,0);
            else
              if(pSSBuffer->uBuffSize!=pSSMsg->uBuffSize){
                ExFreePoolWithTag(pSSBuffer,0);
                pSSBuffer=(PSSMSG)ExAllocatePoolWithTag(NonPagedPool,pSSMsg->uBuffSize,0);
              }
            if(pSSBuffer)
              RtlCopyMemory(pSSBuffer,pSSMsg,pSSMsg->uBuffSize);
            else{
              ntStatus=STATUS_INSUFFICIENT_RESOURCES;
            }
          }
          Irp->IoStatus.Information=MmGetMdlByteCount(Irp->MdlAddress);
        }
      break;
      default:break;
    }
  }
  Irp->IoStatus.Status=ntStatus;
  IofCompleteRequest(Irp,0);
  return 0;
}

VOID DDKAPI DriverUnload(PDRIVER_OBJECT pDriverObject){
  UNICODE_STRING SymbolicLinkName;
  //was loaded ok?
  if(bNotifyRoutineCreated){
    //restore system
    ForceRestoreSystem();
    //remove NotifyRoutine
    PsSetCreateProcessNotifyRoutine(NotifyRoutine,TRUE);
    //remove names
    RtlInitUnicodeString(&SymbolicLinkName,sCreateSymbolicLinkName);
    IoDeleteSymbolicLink(&SymbolicLinkName);
    IoDeleteDevice(pDriverObject->DeviceObject);
  }
}

NTSTATUS DDKAPI CreateClose(PDEVICE_OBJECT DeviceObject,PIRP Irp){
  Irp->IoStatus.Information=0;
  Irp->IoStatus.Status=0;
  IofCompleteRequest(Irp,0);
  return STATUS_SUCCESS;
}

NTSTATUS DDKAPI DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING RegistryPath){
  NTSTATUS NtStatus=STATUS_SUCCESS;
  PDEVICE_OBJECT pDeviceObject=NULL;
  UNICODE_STRING DeviceName,SymbolicLinkName;
  //create named driver...
  pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DeviceControl;
  pDriverObject->MajorFunction[IRP_MJ_CREATE]=CreateClose;
  pDriverObject->MajorFunction[IRP_MJ_CLOSE]=CreateClose;
  pDriverObject->DriverUnload=DriverUnload;
  //initialize name
  RtlInitUnicodeString(&DeviceName,sCreateDeviceName);
  RtlInitUnicodeString(&SymbolicLinkName,sCreateSymbolicLinkName);
  NtStatus=IoCreateDevice(pDriverObject,0,&DeviceName,FILE_DEVICE_UNKNOWN,0,0,&pDeviceObject);
  if(NtStatus==STATUS_SUCCESS){
    NtStatus=IoCreateSymbolicLink(&SymbolicLinkName,&DeviceName);
    if(NtStatus==STATUS_SUCCESS){
      pDeviceObject->Flags&=(~DO_DEVICE_INITIALIZING);
      //create NotifyRoutine
      NtStatus=PsSetCreateProcessNotifyRoutine(NotifyRoutine,FALSE);
      if(NtStatus==STATUS_SUCCESS){
        //initalize events
        bNotifyRoutineCreated=TRUE;
        HideDriver(pDriverObject);
      }else{
        IoDeleteSymbolicLink(&SymbolicLinkName);
        IoDeleteDevice(pDeviceObject);
      }
    }else{
      IoDeleteDevice(pDeviceObject);
    }
  }
  return STATUS_SUCCESS;
}
