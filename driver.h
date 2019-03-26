#ifndef _DRIVER_H_
#define _DRIVER_H_

#include <ddk/ntddk.h>
#include <ddk/ntapi.h>
#include <ddk/ntifs.h>
#include "pstypes.h"

#ifndef _WINGDI_H
#include <wingdi.h>
#endif

#ifndef PACKED
#define PACKED __attribute__ ((packed))
#endif

NTKERNELAPI HANDLE NTAPI PsGetThreadId(IN PETHREAD Thread);

#pragma pack(push,1)

typedef struct PACKED _SSMSG{
  DWORD uBuffSize;
  BITMAPINFO bmi;
  BYTE  pBuffer[];
}SSMSG,*PSSMSG;

typedef struct PACKED _DRIVERMSG{
  DWORD NtDICFOffset;
  DWORD NtQSIOffset;
  DWORD NtOFOffset;
  DWORD NtGCTOffset;
  DWORD NtQITOffset;
  DWORD NtQVMOffset;
  DWORD NtGBBOffset;
  DWORD NtGSDIBTDIOffset;
}DRIVERMSG,*PDRIVERMSG;

#pragma pack(pop)

//===========================================================
//NtDeviceIoControlFile
//===========================================================

// Required to ensure correct PhysicalDrive IOCTL structure
#pragma pack(push,4)

typedef enum _STORAGE_QUERY_TYPE {
  PropertyStandardQuery = 0,
  PropertyExistsQuery,
  PropertyMaskQuery,
  PropertyQueryMaxDefined
} STORAGE_QUERY_TYPE, *PSTORAGE_QUERY_TYPE;

typedef enum _STORAGE_PROPERTY_ID {
  StorageDeviceProperty = 0,
  StorageAdapterProperty
} STORAGE_PROPERTY_ID, *PSTORAGE_PROPERTY_ID;

typedef struct _STORAGE_PROPERTY_QUERY {
  STORAGE_PROPERTY_ID PropertyId;
  STORAGE_QUERY_TYPE QueryType;
  UCHAR AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;

typedef enum _STORAGE_BUS_TYPE {
  BusTypeUnknown = 0x00,
  BusTypeScsi,
  BusTypeAtapi,
  BusTypeAta,
  BusType1394,
  BusTypeSsa,
  BusTypeFibre,
  BusTypeUsb,
  BusTypeRAID,
  BusTypeMaxReserved = 0x7F
} STORAGE_BUS_TYPE, *PSTORAGE_BUS_TYPE;

typedef struct _STORAGE_DEVICE_DESCRIPTOR {
  DWORD Version;
  DWORD Size;
  BYTE DeviceType;
  BYTE DeviceTypeModifier;
  BOOLEAN RemovableMedia;
  BOOLEAN CommandQueueing;
  DWORD VendorIdOffset;
  DWORD ProductIdOffset;
  DWORD ProductRevisionOffset;
  DWORD SerialNumberOffset;
  STORAGE_BUS_TYPE BusType;
  DWORD RawPropertiesLength;
  BYTE RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

#pragma pack(pop)

// Required to ensure correct PhysicalDrive SCSI

#pragma pack(push,8)

typedef struct _SCSI_PASS_THROUGH {
  USHORT  Length;
  UCHAR  ScsiStatus;
  UCHAR  PathId;
  UCHAR  TargetId;
  UCHAR  Lun;
  UCHAR  CdbLength;
  UCHAR  SenseInfoLength;
  UCHAR  DataIn;
  ULONG  DataTransferLength;
  ULONG  TimeOutValue;
  ULONG  DataBufferOffset;//_PTR
  ULONG  SenseInfoOffset;
  UCHAR  Cdb[16];
}SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;

#define NSM_SERIAL_NUMBER_LENGTH        12

typedef struct _SERIALNUMBER {
  UCHAR DeviceType : 5;
  UCHAR PeripheralQualifier : 3;
  UCHAR PageCode;
  UCHAR Reserved;
  UCHAR PageLength;
  UCHAR SerialNumber[NSM_SERIAL_NUMBER_LENGTH];
} SERIALNUMBER, *PSERIALNUMBER;

#pragma pack(pop)

// Required to ensure correct PhysicalDrive SMART

#pragma pack(push,1)

typedef struct _IDEREGS {
  UCHAR bFeaturesReg;
  UCHAR bSectorCountReg;
  UCHAR bSectorNumberReg;
  UCHAR bCylLowReg;
  UCHAR bCylHighReg;
  UCHAR bDriveHeadReg;
  UCHAR bCommandReg;
  UCHAR bReserved;
} IDEREGS, *PIDEREGS, *LPIDEREGS;

typedef struct _SENDCMDINPARAMS {
  ULONG cBufferSize;
  IDEREGS irDriveRegs;
  UCHAR bDriveNumber;
  UCHAR bReserved[3];
  ULONG dwReserved[4];
  UCHAR bBuffer[1];
} SENDCMDINPARAMS, *PSENDCMDINPARAMS, *LPSENDCMDINPARAMS;

typedef struct _DRIVERSTATUS {
  UCHAR bDriverError;
  UCHAR bIDEError;
  UCHAR bReserved[2];
  ULONG dwReserved[2];
} DRIVERSTATUS, *PDRIVERSTATUS, *LPDRIVERSTATUS;

typedef struct _SENDCMDOUTPARAMS {
  ULONG cBufferSize;
  DRIVERSTATUS DriverStatus;
  UCHAR bBuffer[1];
} SENDCMDOUTPARAMS, *PSENDCMDOUTPARAMS, *LPSENDCMDOUTPARAMS;

typedef struct _IDENTIFY_DEVICE_DATA {
  struct {
    USHORT  Reserved1 : 1;
    USHORT  Retired3 : 1;
    USHORT  ResponseIncomplete : 1;
    USHORT  Retired2 : 3;
    USHORT  FixedDevice : 1;
    USHORT  RemovableMedia : 1;
    USHORT  Retired1 : 7;
    USHORT  DeviceType : 1;
  } GeneralConfiguration; // word 0
  USHORT  NumCylinders; // word 1
  USHORT  ReservedWord2;
  USHORT  NumHeads; // word 3
  USHORT  Retired1[2];
  USHORT  NumSectorsPerTrack; // word 6
  USHORT  VendorUnique1[3];
  UCHAR   SerialNumber[20]; // word 10-19
  USHORT  Retired2[2];
  USHORT  Obsolete1;
  UCHAR  FirmwareRevision[8]; // word 23-26
  UCHAR  ModelNumber[40]; // word 27-46
  UCHAR  MaximumBlockTransfer; // word 47
  UCHAR  VendorUnique2;
  USHORT  ReservedWord48;
  struct {
    UCHAR  ReservedByte49;
    UCHAR  DmaSupported : 1;
    UCHAR  LbaSupported : 1;
    UCHAR  IordyDisable : 1;
    UCHAR  IordySupported : 1;
    UCHAR  Reserved1 : 1;
    UCHAR  StandybyTimerSupport : 1;
    UCHAR  Reserved2 : 2;
    USHORT  ReservedWord50;
  } Capabilities; // word 49-50
  USHORT  ObsoleteWords51[2];
  USHORT  TranslationFieldsValid:3; // word 53
  USHORT  Reserved3:13;
  USHORT  NumberOfCurrentCylinders; // word 54
  USHORT  NumberOfCurrentHeads; // word 55
  USHORT  CurrentSectorsPerTrack; // word 56
  ULONG  CurrentSectorCapacity; // word 57
  UCHAR  CurrentMultiSectorSetting; // word 58
  UCHAR  MultiSectorSettingValid : 1;
  UCHAR  ReservedByte59 : 7;
  ULONG  UserAddressableSectors; // word 60-61
  USHORT  ObsoleteWord62;
  USHORT  MultiWordDMASupport : 8; // word 63
  USHORT  MultiWordDMAActive : 8;
  USHORT  AdvancedPIOModes : 8;
  USHORT  ReservedByte64 : 8;
  USHORT  MinimumMWXferCycleTime;
  USHORT  RecommendedMWXferCycleTime;
  USHORT  MinimumPIOCycleTime;
  USHORT  MinimumPIOCycleTimeIORDY;
  USHORT  ReservedWords69[6];
  USHORT  QueueDepth : 5;
  USHORT  ReservedWord75 : 11;
  USHORT  ReservedWords76[4];
  USHORT  MajorRevision;
  USHORT  MinorRevision;
  struct {
    USHORT  SmartCommands : 1;
    USHORT  SecurityMode : 1;
    USHORT  RemovableMedia : 1;
    USHORT  PowerManagement : 1;
    USHORT  Reserved1 : 1;
    USHORT  WriteCache : 1;
    USHORT  LookAhead : 1;
    USHORT  ReleaseInterrupt : 1;
    USHORT  ServiceInterrupt : 1;
    USHORT  DeviceReset : 1;
    USHORT  HostProtectedArea : 1;
    USHORT  Obsolete1 : 1;
    USHORT  WriteBuffer : 1;
    USHORT  ReadBuffer : 1;
    USHORT  Nop : 1;
    USHORT  Obsolete2 : 1;
    USHORT  DownloadMicrocode : 1;
    USHORT  DmaQueued : 1;
    USHORT  Cfa : 1;
    USHORT  AdvancedPm : 1;
    USHORT  Msn : 1;
    USHORT  PowerUpInStandby : 1;
    USHORT  ManualPowerUp : 1;
    USHORT  Reserved2 : 1;
    USHORT  SetMax : 1;
    USHORT  Acoustics : 1;
    USHORT  BigLba : 1;
    USHORT  Resrved3 : 5;
  } CommandSetSupport; // word 82-83
  USHORT  ReservedWord84;
  struct {
    USHORT  SmartCommands : 1;
    USHORT  SecurityMode : 1;
    USHORT  RemovableMedia : 1;
    USHORT  PowerManagement : 1;
    USHORT  Reserved1 : 1;
    USHORT  WriteCache : 1;
    USHORT  LookAhead : 1;
    USHORT  ReleaseInterrupt : 1;
    USHORT  ServiceInterrupt : 1;
    USHORT  DeviceReset : 1;
    USHORT  HostProtectedArea : 1;
    USHORT  Obsolete1 : 1;
    USHORT  WriteBuffer : 1;
    USHORT  ReadBuffer : 1;
    USHORT  Nop : 1;
    USHORT  Obsolete2 : 1;
    USHORT  DownloadMicrocode : 1;
    USHORT  DmaQueued : 1;
    USHORT  Cfa : 1;
    USHORT  AdvancedPm : 1;
    USHORT  Msn : 1;
    USHORT  PowerUpInStandby : 1;
    USHORT  ManualPowerUp : 1;
    USHORT  Reserved2 : 1;
    USHORT  SetMax : 1;
    USHORT  Acoustics : 1;
    USHORT  BigLba : 1;
    USHORT  Resrved3 : 5;
  } CommandSetActive; // word 85-86
  USHORT  ReservedWord87;
  USHORT  UltraDMASupport : 8; // word 88
  USHORT  UltraDMAActive  : 8;
  USHORT  ReservedWord89[4];
  USHORT  HardwareResetResult;
  USHORT  CurrentAcousticValue : 8;
  USHORT  RecommendedAcousticValue : 8;
  USHORT  ReservedWord95[5];
  ULONG  Max48BitLBA[2]; // word 100-103
  USHORT  ReservedWord104[23];
  USHORT  MsnSupport : 2;
  USHORT  ReservedWord127 : 14;
  USHORT  SecurityStatus;
  USHORT  ReservedWord129[126];
  USHORT  Signature : 8;
  USHORT  CheckSum : 8;
} IDENTIFY_DEVICE_DATA, *PIDENTIFY_DEVICE_DATA;

#pragma pack(pop)

typedef NTSTATUS (DDKAPI *tVolumeDeviceToDosName)(PVOID, PUNICODE_STRING);

//===========================================================
//===========================================================

typedef NTSTATUS (NTAPI * NTPROC) ();
typedef NTPROC * PNTPROC;
typedef HANDLE HHOOK;
typedef VOID(* 	WINEVENTPROC )(HWINEVENTHOOK, DWORD, HWND, LONG, LONG, DWORD, DWORD);
#define NTPROC_ sizeof (NTPROC)

typedef struct tag_SYSTEM_SERVICE_TABLE {
  PNTPROC	ServiceTable; // array of entry points to the calls
	PDWORD	CounterTable; // array of usage counters
  ULONG ServiceLimit; // number of table entries
  PCHAR ArgumentTable; // array of argument counts
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE, **PPSYSTEM_SERVICE_TABLE;

typedef struct tag_SERVICE_DESCRIPTOR_TABLE {
  SYSTEM_SERVICE_TABLE ntoskrnl; // main native API table
  SYSTEM_SERVICE_TABLE win32k; // win subsystem, in shadow table
  SYSTEM_SERVICE_TABLE sst3;
  SYSTEM_SERVICE_TABLE sst4;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE, **PPSERVICE_DESCRIPTOR_TABLE;

extern NTOSAPI SYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef struct _KSYSTEM_TIME {
  ULONG LowPart;
  LONG High1Time;
  LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

extern NTOSAPI KSYSTEM_TIME KeTickCount;

typedef struct _SYSTEM_THREADS_INFORMATION {
  LARGE_INTEGER   KernelTime;
  LARGE_INTEGER   UserTime;
  LARGE_INTEGER   CreateTime;
  ULONG           WaitTime;
  PVOID           StartAddress;
  CLIENT_ID       ClientId;
  KPRIORITY       Priority;
  KPRIORITY       BasePriority;
  ULONG           ContextSwitchCount;
  THREAD_STATE    State;
  KWAIT_REASON    WaitReason;
} SYSTEM_THREADS_INFORMATION, *PSYSTEM_THREADS_INFORMATION;

// SystemProcessesAndThreadsInformation
typedef struct _SYSTEM_PROCESSES_INFORMATION {
  ULONG                       NextEntryDelta;
  ULONG                       ThreadCount;
  ULONG                       Reserved1[6];
  LARGE_INTEGER               CreateTime;
  LARGE_INTEGER               UserTime;
  LARGE_INTEGER               KernelTime;
  UNICODE_STRING              ProcessName;
  KPRIORITY                   BasePriority;
  ULONG                       ProcessId;
  ULONG                       InheritedFromProcessId;
  ULONG                       HandleCount;
  ULONG                       SessionId;
  ULONG                       Reserved2;
  VM_COUNTERS                 VmCounters;
#if (VER_PRODUCTBUILD >= 2195)
  IO_COUNTERS                 IoCounters;
#endif // (VER_PRODUCTBUILD >= 2195)
  SYSTEM_THREADS_INFORMATION  Threads[1];
} SYSTEM_PROCESSES_INFORMATION, *PSYSTEM_PROCESSES_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY_64 {
	ULONG	 Unknown[4];
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT  Index;
	USHORT	NameLength;
	USHORT  LoadCount;
	USHORT  PathLength;
	CHAR  ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY_64, *PSYSTEM_MODULE_INFORMATION_ENTRY_64;

typedef struct _SYSTEM_MODULE_INFORMATION_64 {
	ULONG  Count;
  SYSTEM_MODULE_INFORMATION_ENTRY_64 Module[1];
}SYSTEM_MODULE_INFORMATION_64,*PSYSTEM_MODULE_INFORMATION_64;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
  ULONG Count;
  SYSTEM_HANDLE_INFORMATION Handle[1];
}SYSTEM_HANDLE_INFORMATION_EX,*PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _PROCESS_BASIC_INFORMATION_EX {
	NTSTATUS  ExitStatus;
	PPEB  PebBaseAddress;
	KAFFINITY  AffinityMask;
	KPRIORITY  BasePriority;
	ULONG_PTR  UniqueProcessId;
	ULONG_PTR  InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_EX, *PPROCESS_BASIC_INFORMATION_EX;

typedef struct _MEMORY_BASIC_INFORMATION_EX {
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	DWORD     __alignment1;
	ULONG_PTR RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
	DWORD     __alignment2;
} MEMORY_BASIC_INFORMATION_EX,*PMEMORY_BASIC_INFORMATION_EX;

//===========================================================
//===========================================================

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif //OBJ_KERNEL_HANDLE

#define MmMapAddress(a,s) MmMapIoSpace(MmGetPhysicalAddress((PVOID)a),s,MmNonCached)

#define ATA_IDENTIFY_DEVICE 0xEC
#define SCSI_IOCTL_DATA_IN  0x01
#define CDB6GENERIC_LENGTH  0x06
#define SCSIOP_INQUIRY      0x12

#define IOCTL_STORAGE_BASE 0x0000002d
#define IOCTL_DISK_BASE 0x00000007

#define IOCTL_STORAGE_QUERY_PROPERTY \
CTL_CODE(IOCTL_STORAGE_BASE, 0x0500,METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SMART_RCV_DRIVE_DATA \
CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_SCSI_BASE                	FILE_DEVICE_CONTROLLER
#define IOCTL_SCSI_MINIPORT             CTL_CODE(IOCTL_SCSI_BASE, 0x0402, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)   //0x0004D008  see NTDDSCSI.H for definition
#define IOCTL_SCSI_RESCAN_BUS           CTL_CODE(IOCTL_SCSI_BASE, 0x0407, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH         CTL_CODE(IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH_DIRECT  CTL_CODE(IOCTL_SCSI_BASE, 0x0405, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define WDF_TIMEOUT_TO_SEC              ((LONGLONG) 1 * 10 * 1000 * 1000)
#define WDF_TIMEOUT_TO_MS               ((LONGLONG) 1 * 10 * 1000)
#define WDF_TIMEOUT_TO_US               ((LONGLONG) 1 * 10)

#define WDF_REL_TIMEOUT_IN_SEC(Time)    (Time * -1 * WDF_TIMEOUT_TO_SEC)
#define WDF_ABS_TIMEOUT_IN_SEC(Time)    (Time *  1 * WDF_TIMEOUT_TO_SEC)
#define WDF_REL_TIMEOUT_IN_MS(Time)     (Time * -1 * WDF_TIMEOUT_TO_MS)
#define WDF_ABS_TIMEOUT_IN_MS(Time)     (Time *  1 * WDF_TIMEOUT_TO_MS)
#define WDF_REL_TIMEOUT_IN_US(Time)     (Time * -1 * WDF_TIMEOUT_TO_US)
#define WDF_ABS_TIMEOUT_IN_US(Time)     (Time *  1 * WDF_TIMEOUT_TO_US)

//===========================================================
//===========================================================

#define WOW64_CONTEXT_i386 0x00010000

#define WOW64_CONTEXT_CONTROL (WOW64_CONTEXT_i386 | 0x00000001L)
#define WOW64_CONTEXT_INTEGER (WOW64_CONTEXT_i386 | 0x00000002L)
#define WOW64_CONTEXT_SEGMENTS (WOW64_CONTEXT_i386 | 0x00000004L)
#define WOW64_CONTEXT_FLOATING_POINT (WOW64_CONTEXT_i386 | 0x00000008L)
#define WOW64_CONTEXT_DEBUG_REGISTERS (WOW64_CONTEXT_i386 | 0x00000010L)
#define WOW64_CONTEXT_EXTENDED_REGISTERS (WOW64_CONTEXT_i386 | 0x00000020L)

#define WOW64_CONTEXT_FULL (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)

#define WOW64_CONTEXT_ALL (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS | \
WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS | \
WOW64_CONTEXT_EXTENDED_REGISTERS)

#define WOW64_SIZE_OF_80387_REGISTERS         80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512

typedef struct _WOW64_FLOATING_SAVE_AREA {
  DWORD ControlWord;
  DWORD StatusWord;
  DWORD TagWord;
  DWORD ErrorOffset;
  DWORD ErrorSelector;
  DWORD DataOffset;
  DWORD DataSelector;
  BYTE RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
  DWORD Cr0NpxState;
}WOW64_FLOATING_SAVE_AREA,*PWOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT {
  DWORD ContextFlags;

  DWORD Dr0;
  DWORD Dr1;
  DWORD Dr2;
  DWORD Dr3;
  DWORD Dr6;
  DWORD Dr7;

  WOW64_FLOATING_SAVE_AREA FloatSave;

  DWORD SegGs;
  DWORD SegFs;
  DWORD SegEs;
  DWORD SegDs;

  DWORD Edi;
  DWORD Esi;
  DWORD Ebx;
  DWORD Edx;
  DWORD Ecx;
  DWORD Eax;

  DWORD Ebp;
  DWORD Eip;
  DWORD SegCs;
  DWORD EFlags;
  DWORD Esp;
  DWORD SegSs;

  BYTE ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

}WOW64_CONTEXT,*PWOW64_CONTEXT;

//===========================================================
//===========================================================

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#define IMAGE_FIRST_SECTION64(h)          ((PIMAGE_SECTION_HEADER) ((PBYTE)h+FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader)+((PIMAGE_NT_HEADERS)(h))->FileHeader.SizeOfOptionalHeader))

#define CRITICAL_STRUCTURE_CORRUPTION     ((ULONG)0x00000109L)

#define KI_USER_SHARED_DATA_64            0xFFFFF78000000000ULL
#define SharedSystemTime                  (KI_USER_SHARED_DATA_64 + 0x14)
#define KeQuerySystemTime(CurrentCount)   (*((PULONG64)(CurrentCount))=*((volatile ULONG64 *)(SharedSystemTime)))

#define MAX_HOOK_NUMBER   4
#define HOOK_ALIGMENT     16
#define ABS_JUMP_LEN      12
#define ABS_JUMP_LEN2     13

#define CUSTOM_ROP 0xFFFFFFFF //for internal use whit driver...
#define CONTEXT_DEBUG_REGISTERS_EX 0xFFFFFFFF //for internal use whit driver...

#define ThreadWow64Context 29

typedef struct _KERNELMODULEHOOKS{
  PVOID Base;
  ULONG Size;
  PBYTE Space;
  PNTPROC pSST;
  struct _Hook{
    PULARGE_INTEGER NtAPIAddress;
    DWORD FuncOffset;
    DWORD RealOffset;
    PBYTE JmpBuffer;
    BYTE  OrigContent[HOOK_ALIGMENT];
  }Hook[MAX_HOOK_NUMBER];
}KERNELMODULEHOOKS,*PKERNELMODULEHOOKS;

typedef struct _HOOKDATA{
  PSERVICE_DESCRIPTOR_TABLE ServiceDescriptorShadowTable;
  ULONGLONG KiRetireDpcListAddress;
  KERNELMODULEHOOKS ntoskrnl;
  KERNELMODULEHOOKS win32k;
}HOOKDATA,*PHOOKDATA;

typedef struct _HOOK_CTX{
  ULONG64 rax;
  ULONG64 rcx;
  ULONG64 rdx;
  ULONG64 rbx;
  ULONG64 rbp;
  ULONG64 rsi;
  ULONG64 rdi;
  ULONG64 r8;
  ULONG64 r9;
  ULONG64 r10;
  ULONG64 r11;
  ULONG64 r12;
  ULONG64 r13;
  ULONG64 r14;
  ULONG64 r15;
  ULONG64 Rflags;
  ULONG64 rsp;
}HOOK_CTX,*PHOOK_CTX;

#endif //_DRIVER_H_
