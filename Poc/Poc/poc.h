#pragma once

#include "ntstatus.h"
#include "Windows.h"
#include <iostream>

#pragma comment(lib, "ntdll.lib")


#define HIDWORD(l) ((DWORD)(((DWORDLONG)(l)>>32)&0xFFFFFFFF))
#define LODWORD(l) ((DWORD)((DWORDLONG)(l)))

#define AfdOpenPacket "AfdOpenPacketXX"
#define AFD_DEVICE_NAME L"\\Device\\Afd"
#define LOCALHOST "127.0.0.1"


#define IOCTL_AFD_BIND 0x12003LL
#define IOCTL_AFD_LISTEN 0x1200BLL
#define IOCTL_AFD_CONNECT 0x120BBLL
#define IOCTL_AFD_GET_SOCK_NAME 0x1202FLL
#define FSCTL_PIPE_PEEK 0x11400CLL
#define FSCTL_PIPE_IMPERSONATE 0x11001CLL
#define FSCTL_PIPE_INTERNAL_WRITE 0x119FF8

#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_INHERIT 0x00000002
#define FILE_OPEN_IF 0x3
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define OFFSET_IN_TOKEN_VARIABLEPART 0x490
#define OFFSET_IN_TOKEN_TOKEN_PRIVILEGES 0x40
#define OFFSET_IN_TOKEN_PRIMARY_GROUP 0xA8
#define OFFSET_IN_TOKEN_DYNAMIC_PART 0xB0
#define OFFSET_IN_TOKEN_DEFAULT_DACL 0xB8
#define PREVIOUS_MODE_OFFSET 0x232
#define OFFSET_TO_ACTIVE_PROCESS_LINKS 0x448
#define OFFSET_TO_TOKEN 0x4b8
#define CURRENT_THREAD (HANDLE)0xFFFFFFFFFFFFFFFE


typedef struct IO_STATUS_BLOCK
{
    union
    {
        DWORD Status;
        PVOID Pointer;
    };

    DWORD* Information;
};

//0x4 bytes (sizeof)
struct _SYSTEM_POWER_STATE_CONTEXT
{
    union
    {
        struct
        {
            ULONG Reserved1 : 8;                                              //0x0
            ULONG TargetSystemState : 4;                                      //0x0
            ULONG EffectiveSystemState : 4;                                   //0x0
            ULONG CurrentSystemState : 4;                                     //0x0
            ULONG IgnoreHibernationPath : 1;                                  //0x0
            ULONG PseudoTransition : 1;                                       //0x0
            ULONG KernelSoftReboot : 1;                                       //0x0
            ULONG DirectedDripsTransition : 1;                                //0x0
            ULONG Reserved2 : 8;                                              //0x0
        };
        ULONG ContextAsUlong;                                               //0x0
    };
};

//0x4 bytes (sizeof)
union _POWER_STATE
{
    enum _SYSTEM_POWER_STATE SystemState;                                   //0x0
    enum _DEVICE_POWER_STATE DeviceState;                                   //0x0
};

//0x48 bytes (sizeof)
typedef struct _IO_STACK_LOCATION
{
    UCHAR MajorFunction;                                                    //0x0
    UCHAR MinorFunction;                                                    //0x1
    UCHAR Flags;                                                            //0x2
    UCHAR Control;                                                          //0x3
    union
    {
        struct
        {
            struct _IO_SECURITY_CONTEXT* SecurityContext;                   //0x8
            ULONG Options;                                                  //0x10
            USHORT FileAttributes;                                          //0x18
            USHORT ShareAccess;                                             //0x1a
            ULONG EaLength;                                                 //0x20
        } Create;                                                           //0x8
        struct
        {
            struct _IO_SECURITY_CONTEXT* SecurityContext;                   //0x8
            ULONG Options;                                                  //0x10
            USHORT Reserved;                                                //0x18
            USHORT ShareAccess;                                             //0x1a
            struct _NAMED_PIPE_CREATE_PARAMETERS* Parameters;               //0x20
        } CreatePipe;                                                       //0x8
        struct
        {
            struct _IO_SECURITY_CONTEXT* SecurityContext;                   //0x8
            ULONG Options;                                                  //0x10
            USHORT Reserved;                                                //0x18
            USHORT ShareAccess;                                             //0x1a
            struct _MAILSLOT_CREATE_PARAMETERS* Parameters;                 //0x20
        } CreateMailslot;                                                   //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            ULONG Key;                                                      //0x10
            ULONG Flags;                                                    //0x14
            union _LARGE_INTEGER ByteOffset;                                //0x18
        } Read;                                                             //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            ULONG Key;                                                      //0x10
            ULONG Flags;                                                    //0x14
            union _LARGE_INTEGER ByteOffset;                                //0x18
        } Write;                                                            //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            struct _UNICODE_STRING* FileName;                               //0x10
            enum _FILE_INFORMATION_CLASS FileInformationClass;              //0x18
            ULONG FileIndex;                                                //0x20
        } QueryDirectory;                                                   //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            ULONG CompletionFilter;                                         //0x10
        } NotifyDirectory;                                                  //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            ULONG CompletionFilter;                                         //0x10
            enum _DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass; //0x18
        } NotifyDirectoryEx;                                                //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            enum _FILE_INFORMATION_CLASS FileInformationClass;              //0x10
        } QueryFile;                                                        //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            enum _FILE_INFORMATION_CLASS FileInformationClass;              //0x10
            struct _FILE_OBJECT* FileObject;                                //0x18
            union
            {
                struct
                {
                    UCHAR ReplaceIfExists;                                  //0x20
                    UCHAR AdvanceOnly;                                      //0x21
                };
                ULONG ClusterCount;                                         //0x20
                VOID* DeleteHandle;                                         //0x20
            };
        } SetFile;                                                          //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            VOID* EaList;                                                   //0x10
            ULONG EaListLength;                                             //0x18
            ULONG EaIndex;                                                  //0x20
        } QueryEa;                                                          //0x8
        struct
        {
            ULONG Length;                                                   //0x8
        } SetEa;                                                            //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            enum _FSINFOCLASS FsInformationClass;                           //0x10
        } QueryVolume;                                                      //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            enum _FSINFOCLASS FsInformationClass;                           //0x10
        } SetVolume;                                                        //0x8
        struct
        {
            ULONG OutputBufferLength;                                       //0x8
            ULONG InputBufferLength;                                        //0x10
            ULONG FsControlCode;                                            //0x18
            VOID* Type3InputBuffer;                                         //0x20
        } FileSystemControl;                                                //0x8
        struct
        {
            union _LARGE_INTEGER* Length;                                   //0x8
            ULONG Key;                                                      //0x10
            union _LARGE_INTEGER ByteOffset;                                //0x18
        } LockControl;                                                      //0x8
        struct
        {
            ULONG OutputBufferLength;                                       //0x8
            ULONG InputBufferLength;                                        //0x10
            ULONG IoControlCode;                                            //0x18
            VOID* Type3InputBuffer;                                         //0x20
        } DeviceIoControl;                                                  //0x8
        struct
        {
            ULONG SecurityInformation;                                      //0x8
            ULONG Length;                                                   //0x10
        } QuerySecurity;                                                    //0x8
        struct
        {
            ULONG SecurityInformation;                                      //0x8
            VOID* SecurityDescriptor;                                       //0x10
        } SetSecurity;                                                      //0x8
        struct
        {
            struct _VPB* Vpb;                                               //0x8
            struct _DEVICE_OBJECT* DeviceObject;                            //0x10
        } MountVolume;                                                      //0x8
        struct
        {
            struct _VPB* Vpb;                                               //0x8
            struct _DEVICE_OBJECT* DeviceObject;                            //0x10
        } VerifyVolume;                                                     //0x8
        struct
        {
            struct _SCSI_REQUEST_BLOCK* Srb;                                //0x8
        } Scsi;                                                             //0x8
        struct
        {
            ULONG Length;                                                   //0x8
            VOID* StartSid;                                                 //0x10
            struct _FILE_GET_QUOTA_INFORMATION* SidList;                    //0x18
            ULONG SidListLength;                                            //0x20
        } QueryQuota;                                                       //0x8
        struct
        {
            ULONG Length;                                                   //0x8
        } SetQuota;                                                         //0x8
        struct
        {
            enum _DEVICE_RELATION_TYPE Type;                                //0x8
        } QueryDeviceRelations;                                             //0x8
        struct
        {
            struct _GUID* InterfaceType;                                    //0x8
            USHORT Size;                                                    //0x10
            USHORT Version;                                                 //0x12
            struct _INTERFACE* Interface;                                   //0x18
            VOID* InterfaceSpecificData;                                    //0x20
        } QueryInterface;                                                   //0x8
        struct
        {
            struct _DEVICE_CAPABILITIES* Capabilities;                      //0x8
        } DeviceCapabilities;                                               //0x8
        struct
        {
            struct _IO_RESOURCE_REQUIREMENTS_LIST* IoResourceRequirementList; //0x8
        } FilterResourceRequirements;                                       //0x8
        struct
        {
            ULONG WhichSpace;                                               //0x8
            VOID* Buffer;                                                   //0x10
            ULONG Offset;                                                   //0x18
            ULONG Length;                                                   //0x20
        } ReadWriteConfig;                                                  //0x8
        struct
        {
            UCHAR Lock;                                                     //0x8
        } SetLock;                                                          //0x8
        struct
        {
            enum BUS_QUERY_ID_TYPE IdType;                                  //0x8
        } QueryId;                                                          //0x8
        struct
        {
            enum DEVICE_TEXT_TYPE DeviceTextType;                           //0x8
            ULONG LocaleId;                                                 //0x10
        } QueryDeviceText;                                                  //0x8
        struct
        {
            UCHAR InPath;                                                   //0x8
            UCHAR Reserved[3];                                              //0x9
            enum _DEVICE_USAGE_NOTIFICATION_TYPE Type;                      //0x10
        } UsageNotification;                                                //0x8
        struct
        {
            enum _SYSTEM_POWER_STATE PowerState;                            //0x8
        } WaitWake;                                                         //0x8
        struct
        {
            struct _POWER_SEQUENCE* PowerSequence;                          //0x8
        } PowerSequence;                                                    //0x8
        struct
        {
            union
            {
                ULONG SystemContext;                                        //0x8
                struct _SYSTEM_POWER_STATE_CONTEXT SystemPowerStateContext; //0x8
            };
            enum _POWER_STATE_TYPE Type;                                    //0x10
            union _POWER_STATE State;                                       //0x18
            enum POWER_ACTION ShutdownType;                                 //0x20
        } Power;                                                            //0x8
        struct
        {
            struct _CM_RESOURCE_LIST* AllocatedResources;                   //0x8
            struct _CM_RESOURCE_LIST* AllocatedResourcesTranslated;         //0x10
        } StartDevice;                                                      //0x8
        struct
        {
            ULONGLONG ProviderId;                                           //0x8
            VOID* DataPath;                                                 //0x10
            ULONG BufferSize;                                               //0x18
            VOID* Buffer;                                                   //0x20
        } WMI;                                                              //0x8
        struct
        {
            VOID* Argument1;                                                //0x8
            VOID* Argument2;                                                //0x10
            VOID* Argument3;                                                //0x18
            VOID* Argument4;                                                //0x20
        } Others;                                                           //0x8
    } Parameters;                                                           //0x8
    struct _DEVICE_OBJECT* DeviceObject;                                    //0x28
    struct _FILE_OBJECT* FileObject;                                        //0x30
    LONG(*CompletionRoutine)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2, VOID* arg3); //0x38
    VOID* Context;                                                          //0x40
}IO_STACK_LOCATION;

//0x18 bytes (sizeof)
struct _KDEVICE_QUEUE_ENTRY
{
    struct _LIST_ENTRY DeviceListEntry;                                     //0x0
    ULONG SortKey;                                                          //0x10
    UCHAR Inserted;                                                         //0x14
};

//0x58 bytes (sizeof)
struct _KAPC
{
    UCHAR Type;                                                             //0x0
    UCHAR AllFlags;                                                         //0x1
    UCHAR Size;                                                             //0x2
    UCHAR SpareByte1;                                                       //0x3
    ULONG SpareLong0;                                                       //0x4
    struct _KTHREAD* Thread;                                                //0x8
    struct _LIST_ENTRY ApcListEntry;                                        //0x10
    VOID* Reserved[3];                                                      //0x20
    VOID* NormalContext;                                                    //0x38
    VOID* SystemArgument1;                                                  //0x40
    VOID* SystemArgument2;                                                  //0x48
    CHAR ApcStateIndex;                                                     //0x50
    CHAR ApcMode;                                                           //0x51
    UCHAR Inserted;                                                         //0x52
};
//0xd0 bytes (sizeof)
struct _IRP
{
    SHORT Type;                                                             //0x0
    USHORT Size;                                                            //0x2
    USHORT AllocationProcessorNumber;                                       //0x4
    USHORT Reserved;                                                        //0x6
    struct _MDL* MdlAddress;                                                //0x8
    ULONG Flags;                                                            //0x10
    union
    {
        struct _IRP* MasterIrp;                                             //0x18
        LONG IrpCount;                                                      //0x18
        VOID* SystemBuffer;                                                 //0x18
    } AssociatedIrp;                                                        //0x18
    struct _LIST_ENTRY ThreadListEntry;                                     //0x20
    struct IO_STATUS_BLOCK IoStatus;                                       //0x30
    CHAR RequestorMode;                                                     //0x40
    UCHAR PendingReturned;                                                  //0x41
    CHAR StackCount;                                                        //0x42
    CHAR CurrentLocation;                                                   //0x43
    UCHAR Cancel;                                                           //0x44
    UCHAR CancelIrql;                                                       //0x45
    CHAR ApcEnvironment;                                                    //0x46
    UCHAR AllocationFlags;                                                  //0x47
    union
    {
        struct _IO_STATUS_BLOCK* UserIosb;                                  //0x48
        VOID* IoRingContext;                                                //0x48
    };
    struct _KEVENT* UserEvent;                                              //0x50
    union
    {
        struct
        {
            union
            {
                VOID(*UserApcRoutine)(VOID* arg1, struct _IO_STATUS_BLOCK* arg2, ULONG arg3); //0x58
                VOID* IssuingProcess;                                       //0x58
            };
            union
            {
                VOID* UserApcContext;                                       //0x60
                struct _IORING_OBJECT* IoRing;                              //0x60
            };
        } AsynchronousParameters;                                           //0x58
        union _LARGE_INTEGER AllocationSize;                                //0x58
    } Overlay;                                                              //0x58
    VOID(*CancelRoutine)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2);  //0x68
    VOID* UserBuffer;                                                       //0x70
    union
    {
        struct
        {
            union
            {
                struct _KDEVICE_QUEUE_ENTRY DeviceQueueEntry;               //0x78
                VOID* DriverContext[4];                                     //0x78
            };
            struct _ETHREAD* Thread;                                        //0x98
            CHAR* AuxiliaryBuffer;                                          //0xa0
            struct _LIST_ENTRY ListEntry;                                   //0xa8
            union
            {
                struct _IO_STACK_LOCATION* CurrentStackLocation;            //0xb8
                ULONG PacketType;                                           //0xb8
            };
            struct _FILE_OBJECT* OriginalFileObject;                        //0xc0
            VOID* IrpExtension;                                             //0xc8
        } Overlay;                                                          //0x78
        struct _KAPC Apc;                                                   //0x78
        VOID* CompletionKey;                                                //0x78
    } Tail;                                                                 //0x78
};
typedef struct _TA_ADDRESS
{
    USHORT AddressLength;
    USHORT AddressType;
    UCHAR Address[1];
}TA_ADDRESS;

typedef struct _TRANSPORT_ADDRESS
{
    LONG TAAddressCount;
    TA_ADDRESS Address[1];
}TRANSPORT_ADDRESS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
}OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _AFD_CREATE_PACKET {
    //FILE_FULL_EA_INFORMATION
    ULONG  NextEntryOffset;
    WORD  Flags;
    UCHAR  EaNameLength;
    USHORT EaValueLength;
    CHAR   EaName[15];

    //AFD_CREATE_PACKET
    ULONG EndpointFlags;
    ULONG GroupID;
    ULONG AddressFamily;
    ULONG SocketType;
    ULONG Protocol;
    ULONG SizeOfTransportName;
    wchar_t TransportName[16];
    //UCHAR Unkown;
} AFD_CREATE_PACKET;

enum THREADINFOCLASS { ThreadImpersonationToken = 5 };

enum SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11,
    SystemExtendedHandleInformation = 64
};

typedef enum EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
};

typedef struct _AFD_BIND_DATA {
    ULONG		ShareType;
    SOCKADDR_IN addr;
} AFD_BIND_DATA, * PAFD_BIND_DATA;

typedef struct alignas(16) MY_AFD_CONNECT_INFO
{
    __int64 UseSan;
    __int64 hNtSock1;
    __int64 Unknown;
    __int32 tmp6;
    WORD const_16;
    sockaddr_in bind;
};


typedef struct FAKE_DATA_ENTRY_QUEUE
{
    DWORD tmp;
    LIST_ENTRY nextQueue;
    __int64 unknown;
    PVOID security_client_context;
    __int64 unknown2;
    __int64 sizeOfData;
    char DATA[0x77FD0];
};

typedef struct _AFD_LISTEN_INFO {

    ULONG unknown;
    __int64 MaximumConnectionQueue;
} AFD_LISTEN_INFO, * PAFD_LISTEN_INFO;






typedef struct _SECURITY_CLIENT_CONTEXT
{
    _SECURITY_QUALITY_OF_SERVICE SecurityQos;
    void* ClientToken;
    unsigned __int8 DirectlyAccessClientToken;
    unsigned __int8 DirectAccessEffectiveOnly;
    unsigned __int8 ServerIsRemote;
    _TOKEN_CONTROL ClientTokenControl;
}SECURITY_CLIENT_CONTEXT, * PSECURITY_CLIENT_CONTEXT;

struct __declspec(align(8)) _OWNER_ENTRY
{
    unsigned __int64 OwnerThread;
    DWORD ___u1;
};


//0x68 bytes (sizeof)
typedef struct _ERESOURCE
{
    struct _LIST_ENTRY SystemResourcesList;                                 //0x0
    struct _OWNER_ENTRY* OwnerTable;                                        //0x10
    SHORT ActiveCount;                                                      //0x18
    union
    {
        USHORT Flag;                                                        //0x1a
        struct
        {
            UCHAR ReservedLowFlags;                                         //0x1a
            UCHAR WaiterPriority;                                           //0x1b
        };
    };
    VOID* SharedWaiters;                                                    //0x20
    VOID* ExclusiveWaiters;                                                 //0x28
    struct _OWNER_ENTRY OwnerEntry;                                         //0x30
    ULONG ActiveEntries;                                                    //0x40
    ULONG ContentionCount;                                                  //0x44
    ULONG NumberOfSharedWaiters;                                            //0x48
    ULONG NumberOfExclusiveWaiters;                                         //0x4c
    VOID* Reserved2;                                                        //0x50
    union
    {
        VOID* Address;                                                      //0x58
        ULONGLONG CreatorBackTraceIndex;                                    //0x58
    };
    ULONGLONG SpinLock;                                                     //0x60
}ERESOURCE, *PERESOURCE;

//0x8 bytes (sizeof)
typedef struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x10 bytes (sizeof)
typedef struct _SEP_CACHED_HANDLES_TABLE
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _RTL_DYNAMIC_HASH_TABLE* HashTable;                              //0x8
};

//0x8 bytes (sizeof)
typedef struct _EX_RUNDOWN_REF
{
    union
    {
        ULONGLONG Count;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x20 bytes (sizeof)
typedef struct _OB_HANDLE_REVOCATION_BLOCK
{
    struct _LIST_ENTRY RevocationInfos;                                     //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    struct _EX_RUNDOWN_REF Rundown;                                         //0x18
};

//0xc0 bytes (sizeof)
typedef struct _SEP_LOGON_SESSION_REFERENCES
{
    struct _SEP_LOGON_SESSION_REFERENCES* Next;                             //0x0
    struct _LUID LogonId;                                                   //0x8
    struct _LUID BuddyLogonId;                                              //0x10
    LONGLONG ReferenceCount;                                                //0x18
    ULONG Flags;                                                            //0x20
    struct _DEVICE_MAP* pDeviceMap;                                         //0x28
    VOID* Token;                                                            //0x30
    struct _UNICODE_STRING AccountName;                                     //0x38
    struct _UNICODE_STRING AuthorityName;                                   //0x48
    struct _SEP_CACHED_HANDLES_TABLE CachedHandlesTable;                    //0x58
    struct _EX_PUSH_LOCK SharedDataLock;                                    //0x68
    struct _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION* SharedClaimAttributes;  //0x70
    struct _SEP_SID_VALUES_BLOCK* SharedSidValues;                          //0x78
    struct _OB_HANDLE_REVOCATION_BLOCK RevocationBlock;                     //0x80
    struct _EJOB* ServerSilo;                                               //0xa0
    struct _LUID SiblingAuthId;                                             //0xa8
    struct _LIST_ENTRY TokenList;                                           //0xb0
};
//0x30 bytes (sizeof)
typedef struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
{
    ULONG SecurityAttributeCount;                                           //0x0
    struct _LIST_ENTRY SecurityAttributesList;                              //0x8
    ULONG WorkingSecurityAttributeCount;                                    //0x18
    struct _LIST_ENTRY WorkingSecurityAttributesList;                       //0x20
}AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION;

//0x20 bytes (sizeof)
typedef struct _SEP_SID_VALUES_BLOCK
{
    ULONG BlockLength;                                                      //0x0
    LONGLONG ReferenceCount;                                                //0x8
    ULONG SidCount;                                                         //0x10
    ULONGLONG SidValuesStart;                                               //0x18
}SEP_SID_VALUES_BLOCK,*PSEP_SID_VALUES_BLOCK;

//0x18 bytes (sizeof)
struct _SEP_TOKEN_PRIVILEGES
{
    ULONGLONG Present;                                                      //0x0
    ULONGLONG Enabled;                                                      //0x8
    ULONGLONG EnabledByDefault;                                             //0x10
};

//0x1f bytes (sizeof)
struct _SEP_AUDIT_POLICY
{
    struct _TOKEN_AUDIT_POLICY AdtTokenPolicy;                              //0x0
    UCHAR PolicySetStatus;                                                  //0x1e
};

//0x498 bytes (sizeof)
struct _TOKEN
{
    struct _TOKEN_SOURCE TokenSource;                                       //0x0
    struct _LUID TokenId;                                                   //0x10
    struct _LUID AuthenticationId;                                          //0x18
    struct _LUID ParentTokenId;                                             //0x20
    union _LARGE_INTEGER ExpirationTime;                                    //0x28
    struct _ERESOURCE* TokenLock;                                           //0x30
    struct _LUID ModifiedId;                                                //0x38
    struct _SEP_TOKEN_PRIVILEGES Privileges;                                //0x40
    struct _SEP_AUDIT_POLICY AuditPolicy;                                   //0x58
    ULONG SessionId;                                                        //0x78
    ULONG UserAndGroupCount;                                                //0x7c
    ULONG RestrictedSidCount;                                               //0x80
    ULONG VariableLength;                                                   //0x84
    ULONG DynamicCharged;                                                   //0x88
    ULONG DynamicAvailable;                                                 //0x8c
    ULONG DefaultOwnerIndex;                                                //0x90
    struct _SID_AND_ATTRIBUTES* UserAndGroups;                              //0x98
    struct _SID_AND_ATTRIBUTES* RestrictedSids;                             //0xa0
    VOID* PrimaryGroup;                                                     //0xa8
    ULONG* DynamicPart;                                                     //0xb0
    struct _ACL* DefaultDacl;                                               //0xb8
    enum _TOKEN_TYPE TokenType;                                             //0xc0
    enum _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;                  //0xc4
    ULONG TokenFlags;                                                       //0xc8
    UCHAR TokenInUse;                                                       //0xcc
    ULONG IntegrityLevelIndex;                                              //0xd0
    ULONG MandatoryPolicy;                                                  //0xd4
    void* LogonSession;                     //0xd8
    struct _LUID OriginatingLogonSession;                                   //0xe0
    struct _SID_AND_ATTRIBUTES_HASH SidHash;                                //0xe8
    struct _SID_AND_ATTRIBUTES_HASH RestrictedSidHash;                      //0x1f8
    struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes; //0x308
    VOID* Package;                                                          //0x310
    struct _SID_AND_ATTRIBUTES* Capabilities;                               //0x318
    ULONG CapabilityCount;                                                  //0x320
    struct _SID_AND_ATTRIBUTES_HASH CapabilitiesHash;                       //0x328
    struct _SEP_LOWBOX_NUMBER_ENTRY* LowboxNumberEntry;                     //0x438
    struct _SEP_CACHED_HANDLES_ENTRY* LowboxHandlesEntry;                   //0x440
    struct _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION* pClaimAttributes;       //0x448
    VOID* TrustLevelSid;                                                    //0x450
    struct _TOKEN* TrustLinkedToken;                                        //0x458
    VOID* IntegrityLevelSidValue;                                           //0x460
    struct _SEP_SID_VALUES_BLOCK* TokenSidValues;                           //0x468
    struct _SEP_LUID_TO_INDEX_MAP_ENTRY* IndexEntry;                        //0x470
    struct _SEP_TOKEN_DIAG_TRACK_ENTRY* DiagnosticInfo;                     //0x478
    struct _SEP_CACHED_HANDLES_ENTRY* BnoIsolationHandlesEntry;             //0x480
    VOID* SessionObject;                                                    //0x488
    ULONGLONG VariablePart;                                                 //0x490
};

//0x38 bytes (sizeof)
struct _OBJECT_HEADER
{
    LONGLONG PointerCount;                                                  //0x0
    union
    {
        LONGLONG HandleCount;                                               //0x8
        VOID* NextToFree;                                                   //0x8
    };
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    UCHAR TypeIndex;                                                        //0x18
    union
    {
        UCHAR TraceFlags;                                                   //0x19
        struct
        {
            UCHAR DbgRefTrace : 1;                                            //0x19
            UCHAR DbgTracePermanent : 1;                                      //0x19
        };
    };
    UCHAR InfoMask;                                                         //0x1a
    union
    {
        UCHAR Flags;                                                        //0x1b
        struct
        {
            UCHAR NewObject : 1;                                              //0x1b
            UCHAR KernelObject : 1;                                           //0x1b
            UCHAR KernelOnlyAccess : 1;                                       //0x1b
            UCHAR ExclusiveObject : 1;                                        //0x1b
            UCHAR PermanentObject : 1;                                        //0x1b
            UCHAR DefaultSecurityQuota : 1;                                   //0x1b
            UCHAR SingleHandleEntry : 1;                                      //0x1b
            UCHAR DeletedInline : 1;                                          //0x1b
        };
    };
    ULONG Reserved;                                                         //0x1c
    union
    {
        struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
        VOID* QuotaBlockCharged;                                            //0x20
    };
    VOID* SecurityDescriptor;                                               //0x28
    struct _TOKEN Body;                                                      //0x30
};

struct mm {
    void* fake_data_entry;
    void* input;
    _IRP* crafted_irp;
    IO_STACK_LOCATION *crafted_arbitrary_io_stack_location;
    void* p_mem_0x30;
    void* p_mem_0xD0_2;
    _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes;
    ACL* VariablePartDefaultDacl;
    ACL* VariablePartDefaultDacl2;
    _ERESOURCE* TokenLock;
    void* PrimaryGroup;
    int sizeOfClientTokenAndObjectHeader;
    PSEP_SID_VALUES_BLOCK TokenSidValues;
    _SECURITY_CLIENT_CONTEXT* security_client_context;
    _SEP_LOGON_SESSION_REFERENCES* LogonSession;
    _TOKEN* fakeToken;
    void *pipe_100_im_control_block;
    void* pipe_100_rw_control_block;
    void* p_mem_Pipe_hToPipe_1000_rw;
    void* p_mem_Pipe_hToPipe_1000_rw_2;
    HANDLE hPipeIM;
    HANDLE hPipeRW;
    HANDLE hFileIM;
    HANDLE hFileRW;
    HANDLE IncPrimitiveTOKEN;
    HANDLE RWPrimitiveTOKEN;
};

//0x18 bytes (sizeof)
struct _DISPATCHER_HEADER
{
    union
    {
        volatile LONG Lock;                                                 //0x0
        LONG LockNV;                                                        //0x0
        struct
        {
            UCHAR Type;                                                     //0x0
            UCHAR Signalling;                                               //0x1
            UCHAR Size;                                                     //0x2
            UCHAR Reserved1;                                                //0x3
        };
        struct
        {
            UCHAR TimerType;                                                //0x0
            union
            {
                UCHAR TimerControlFlags;                                    //0x1
                struct
                {
                    UCHAR Absolute : 1;                                       //0x1
                    UCHAR Wake : 1;                                           //0x1
                    UCHAR EncodedTolerableDelay : 6;                          //0x1
                };
            };
            UCHAR Hand;                                                     //0x2
            union
            {
                UCHAR TimerMiscFlags;                                       //0x3
                struct
                {
                    UCHAR Index : 6;                                          //0x3
                    UCHAR Inserted : 1;                                       //0x3
                    volatile UCHAR Expired : 1;                               //0x3
                };
            };
        };
        struct
        {
            UCHAR Timer2Type;                                               //0x0
            union
            {
                UCHAR Timer2Flags;                                          //0x1
                struct
                {
                    UCHAR Timer2Inserted : 1;                                 //0x1
                    UCHAR Timer2Expiring : 1;                                 //0x1
                    UCHAR Timer2CancelPending : 1;                            //0x1
                    UCHAR Timer2SetPending : 1;                               //0x1
                    UCHAR Timer2Running : 1;                                  //0x1
                    UCHAR Timer2Disabled : 1;                                 //0x1
                    UCHAR Timer2ReservedFlags : 2;                            //0x1
                };
            };
            UCHAR Timer2ComponentId;                                        //0x2
            UCHAR Timer2RelativeId;                                         //0x3
        };
        struct
        {
            UCHAR QueueType;                                                //0x0
            union
            {
                UCHAR QueueControlFlags;                                    //0x1
                struct
                {
                    UCHAR Abandoned : 1;                                      //0x1
                    UCHAR DisableIncrement : 1;                               //0x1
                    UCHAR QueueReservedControlFlags : 6;                      //0x1
                };
            };
            UCHAR QueueSize;                                                //0x2
            UCHAR QueueReserved;                                            //0x3
        };
        struct
        {
            UCHAR ThreadType;                                               //0x0
            UCHAR ThreadReserved;                                           //0x1
            union
            {
                UCHAR ThreadControlFlags;                                   //0x2
                struct
                {
                    UCHAR CycleProfiling : 1;                                 //0x2
                    UCHAR CounterProfiling : 1;                               //0x2
                    UCHAR GroupScheduling : 1;                                //0x2
                    UCHAR AffinitySet : 1;                                    //0x2
                    UCHAR Tagged : 1;                                         //0x2
                    UCHAR EnergyProfiling : 1;                                //0x2
                    UCHAR SchedulerAssist : 1;                                //0x2
                    UCHAR ThreadReservedControlFlags : 1;                     //0x2
                };
            };
            union
            {
                UCHAR DebugActive;                                          //0x3
                struct
                {
                    UCHAR ActiveDR7 : 1;                                      //0x3
                    UCHAR Instrumented : 1;                                   //0x3
                    UCHAR Minimal : 1;                                        //0x3
                    UCHAR Reserved4 : 2;                                      //0x3
                    UCHAR AltSyscall : 1;                                     //0x3
                    UCHAR Emulation : 1;                                      //0x3
                    UCHAR Reserved5 : 1;                                      //0x3
                };
            };
        };
        struct
        {
            UCHAR MutantType;                                               //0x0
            UCHAR MutantSize;                                               //0x1
            UCHAR DpcActive;                                                //0x2
            UCHAR MutantReserved;                                           //0x3
        };
    };
    LONG SignalState;                                                       //0x4
    struct _LIST_ENTRY WaitListHead;                                        //0x8
};
//0x18 bytes (sizeof)
struct _KEVENT
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
};

//0xd8 bytes (sizeof)
struct _FILE_OBJECT
{
    SHORT Type;                                                             //0x0
    SHORT Size;                                                             //0x2
    struct _DEVICE_OBJECT* DeviceObject;                                    //0x8
    struct _VPB* Vpb;                                                       //0x10
    VOID* FsContext;                                                        //0x18
    VOID* FsContext2;                                                       //0x20
    struct _SECTION_OBJECT_POINTERS* SectionObjectPointer;                  //0x28
    VOID* PrivateCacheMap;                                                  //0x30
    LONG FinalStatus;                                                       //0x38
    struct _FILE_OBJECT* RelatedFileObject;                                 //0x40
    UCHAR LockOperation;                                                    //0x48
    UCHAR DeletePending;                                                    //0x49
    UCHAR ReadAccess;                                                       //0x4a
    UCHAR WriteAccess;                                                      //0x4b
    UCHAR DeleteAccess;                                                     //0x4c
    UCHAR SharedRead;                                                       //0x4d
    UCHAR SharedWrite;                                                      //0x4e
    UCHAR SharedDelete;                                                     //0x4f
    ULONG Flags;                                                            //0x50
    struct _UNICODE_STRING FileName;                                        //0x58
    union _LARGE_INTEGER CurrentByteOffset;                                 //0x68
    ULONG Waiters;                                                          //0x70
    ULONG Busy;                                                             //0x74
    VOID* LastLock;                                                         //0x78
    struct _KEVENT Lock;                                                    //0x80
    struct _KEVENT Event;                                                   //0x98
    struct _IO_COMPLETION_CONTEXT* CompletionContext;                       //0xb0
    ULONGLONG IrpListLock;                                                  //0xb8
    struct _LIST_ENTRY IrpList;                                             //0xc0
    VOID* FileObjectExtension;                                              //0xd0
};

typedef struct {
    uint64_t Flink;
    uint64_t Blink;
    _IRP* Irp;
    uint64_t SecurityContext;
    uint32_t EntryType;
    uint32_t QuotaInEntry;
    uint32_t DataSize;
    uint32_t x;
} DATA_QUEUE_ENTRY;

//0x1 bytes (sizeof)
union _KEXECUTE_OPTIONS
{
    UCHAR ExecuteDisable : 1;                                                 //0x0
    UCHAR ExecuteEnable : 1;                                                  //0x0
    UCHAR DisableThunkEmulation : 1;                                          //0x0
    UCHAR Permanent : 1;                                                      //0x0
    UCHAR ExecuteDispatchEnable : 1;                                          //0x0
    UCHAR ImageDispatchEnable : 1;                                            //0x0
    UCHAR DisableExceptionChainValidation : 1;                                //0x0
    UCHAR Spare : 1;                                                          //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
    UCHAR ExecuteOptionsNV;                                                 //0x0
};

struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    union
    {
        ULONGLONG Bitmap[1];                                                //0x8
        ULONGLONG StaticBitmap[32];                                         //0x8
    };
};
//0x438 bytes (sizeof)
struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    struct _LIST_ENTRY ReadyListHead;                                       //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x170
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                          //0x278
            ULONG DisableBoost : 1;                                           //0x278
            ULONG DisableQuantum : 1;                                         //0x278
            ULONG DeepFreeze : 1;                                             //0x278
            ULONG TimerVirtualization : 1;                                    //0x278
            ULONG CheckStackExtents : 1;                                      //0x278
            ULONG CacheIsolationEnabled : 1;                                  //0x278
            ULONG PpmPolicy : 4;                                              //0x278
            ULONG VaSpaceDeleted : 1;                                         //0x278
            ULONG MultiGroup : 1;                                             //0x278
            ULONG ReservedFlags : 19;                                         //0x278
        };
        volatile LONG ProcessFlags;                                         //0x278
    };
    ULONG ActiveGroupsMask;                                                 //0x27c
    CHAR BasePriority;                                                      //0x280
    CHAR QuantumReset;                                                      //0x281
    CHAR Visited;                                                           //0x282
    union _KEXECUTE_OPTIONS Flags;                                          //0x283
    USHORT ThreadSeed[32];                                                  //0x284
    USHORT IdealProcessor[32];                                              //0x2c4
    USHORT IdealNode[32];                                                   //0x304
    USHORT IdealGlobalNode;                                                 //0x344
    USHORT Spare1;                                                          //0x346
    void* StackCount;                                 //0x348
    struct _LIST_ENTRY ProcessListEntry;                                    //0x350
    ULONGLONG CycleTime;                                                    //0x360
    ULONGLONG ContextSwitches;                                              //0x368
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
    ULONG FreezeCount;                                                      //0x378
    ULONG KernelTime;                                                       //0x37c
    ULONG UserTime;                                                         //0x380
    ULONG ReadyTime;                                                        //0x384
    ULONGLONG UserDirectoryTableBase;                                       //0x388
    UCHAR AddressPolicy;                                                    //0x390
    UCHAR Spare2[71];                                                       //0x391
    VOID* InstrumentationCallback;                                          //0x3d8
    union
    {
        ULONGLONG SecureHandle;                                             //0x3e0
        struct
        {
            ULONGLONG SecureProcess : 1;                                      //0x3e0
            ULONGLONG Unused : 1;                                             //0x3e0
        } Flags;                                                            //0x3e0
    } SecureState;                                                          //0x3e0
    ULONGLONG KernelWaitTime;                                               //0x3e8
    ULONGLONG UserWaitTime;                                                 //0x3f0
    ULONGLONG LastRebalanceQpc;                                             //0x3f8
    VOID* PerProcessorCycleTimes;                                           //0x400
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x408
    USHORT PrimaryGroup;                                                    //0x410
    USHORT Spare3[3];                                                       //0x412
    VOID* UserCetLogging;                                                   //0x418
    struct _LIST_ENTRY CpuPartitionList;                                    //0x420
    ULONGLONG EndPadding[1];                                                //0x430
};

//0x1 bytes (sizeof)
union _KWAIT_STATUS_REGISTER
{
    UCHAR Flags;                                                            //0x0
    UCHAR State : 3;                                                          //0x0
    UCHAR Affinity : 1;                                                       //0x0
    UCHAR Priority : 1;                                                       //0x0
    UCHAR Apc : 1;                                                            //0x0
    UCHAR UserApc : 1;                                                        //0x0
    UCHAR Alert : 1;                                                          //0x0
};
//0x30 bytes (sizeof)
struct _KAPC_STATE
{
    struct _LIST_ENTRY ApcListHead[2];                                      //0x0
    struct _KPROCESS* Process;                                              //0x20
    union
    {
        UCHAR InProgressFlags;                                              //0x28
        struct
        {
            UCHAR KernelApcInProgress : 1;                                    //0x28
            UCHAR SpecialApcInProgress : 1;                                   //0x28
        };
    };
    UCHAR KernelApcPending;                                                 //0x29
    union
    {
        UCHAR UserApcPendingAll;                                            //0x2a
        struct
        {
            UCHAR SpecialUserApcPending : 1;                                  //0x2a
            UCHAR UserApcPending : 1;                                         //0x2a
        };
    };
};
//0x40 bytes (sizeof)
struct _KTIMER
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    union _ULARGE_INTEGER DueTime;                                          //0x18
    struct _LIST_ENTRY TimerListEntry;                                      //0x20
    struct _KDPC* Dpc;                                                      //0x30
    USHORT Processor;                                                       //0x38
    USHORT TimerType;                                                       //0x3a
    ULONG Period;                                                           //0x3c
};
//0x30 bytes (sizeof)
struct _KWAIT_BLOCK
{
    struct _LIST_ENTRY WaitListEntry;                                       //0x0
    UCHAR WaitType;                                                         //0x10
    volatile UCHAR BlockState;                                              //0x11
    USHORT WaitKey;                                                         //0x12
    LONG SpareLong;                                                         //0x14
    union
    {
        struct _KTHREAD* Thread;                                            //0x18
        struct _KQUEUE* NotificationQueue;                                  //0x18
        struct _KDPC* Dpc;                                                  //0x18
    };
    VOID* Object;                                                           //0x20
    VOID* SparePtr;                                                         //0x28
};
//0x480 bytes (sizeof)
struct _KTHREAD
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG SecureThread : 1;                                           //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG Spare : 1;                                                  //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetUserShadowStack : 1;                                     //0x74
            ULONG BypassProcessFreeze : 1;                                    //0x74
            ULONG CetKernelShadowStack : 1;                                   //0x74
            ULONG StateSaveAreaDecoupled : 1;                                 //0x74
            ULONG Reserved : 8;                                               //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG UserIdealProcessorFixed : 1;                                //0x78
            ULONG IsolationWidth : 1;                                         //0x78
            ULONG AutoAlignment : 1;                                          //0x78
            ULONG DisableBoost : 1;                                           //0x78
            ULONG AlertedByThreadId : 1;                                      //0x78
            ULONG QuantumDonation : 1;                                        //0x78
            ULONG EnableStackSwap : 1;                                        //0x78
            ULONG GuiThread : 1;                                              //0x78
            ULONG DisableQuantum : 1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
            ULONG DeferPreemption : 1;                                        //0x78
            ULONG QueueDeferPreemption : 1;                                   //0x78
            ULONG ForceDeferSchedule : 1;                                     //0x78
            ULONG SharedReadyQueueAffinity : 1;                               //0x78
            ULONG FreezeCount : 1;                                            //0x78
            ULONG TerminationApcRequest : 1;                                  //0x78
            ULONG AutoBoostEntriesExhausted : 1;                              //0x78
            ULONG KernelStackResident : 1;                                    //0x78
            ULONG TerminateRequestReason : 2;                                 //0x78
            ULONG ProcessStackCountDecremented : 1;                           //0x78
            ULONG RestrictedGuiThread : 1;                                    //0x78
            ULONG VpBackingThread : 1;                                        //0x78
            ULONG EtwStackTraceCrimsonApcDisabled : 1;                        //0x78
            ULONG EtwStackTraceApcInserted : 8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode : 1;                                //0x7f
            UCHAR SpecCtrlSpare : 7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill[43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
        struct _LIST_ENTRY WaitListEntry;                                   //0xd8
        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
        struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4[20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5[68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6[116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7[164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8[40];                                       //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9[88];                                       //0x140
            struct _XSTATE_SAVE* XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10[136];                                     //0x140
            VOID* volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11[176];                                     //0x140
            ULONGLONG Spare18;                                              //0x1f0
            ULONGLONG Spare19;                                              //0x1f8
        };
    };
    union
    {
        volatile LONG ThreadFlags2;                                         //0x200
        struct
        {
            ULONG BamQosLevel : 8;                                            //0x200
            ULONG ThreadFlags2Reserved : 24;                                  //0x200
        };
    };
    UCHAR HgsFeedbackClass;                                                 //0x204
    UCHAR Spare23[3];                                                       //0x205
    struct _LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x218
            ULONG SharedReadyQueue : 1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    struct _KAFFINITY_EX* UserAffinity;                                     //0x228
    USHORT UserAffinityPrimaryGroup;                                        //0x230
    CHAR PreviousMode;                                                      //0x232
    CHAR BasePriority;                                                      //0x233
    union
    {
        CHAR PriorityDecrement;                                             //0x234
        struct
        {
            UCHAR ForegroundBoost : 4;                                        //0x234
            UCHAR UnusualBoost : 4;                                           //0x234
        };
    };
    UCHAR Preempted;                                                        //0x235
    UCHAR AdjustReason;                                                     //0x236
    CHAR AdjustIncrement;                                                   //0x237
    ULONGLONG AffinityVersion;                                              //0x238
    struct _KAFFINITY_EX* Affinity;                                         //0x240
    USHORT AffinityPrimaryGroup;                                            //0x248
    UCHAR ApcStateIndex;                                                    //0x24a
    UCHAR WaitBlockCount;                                                   //0x24b
    ULONG IdealProcessor;                                                   //0x24c
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill[43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        struct _KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3[64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4[72];                                    //0x288
            VOID* LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5[83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
    struct _LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    union
    {
        UCHAR FreezeFlags;                                                  //0x31a
        struct
        {
            UCHAR FreezeCount2 : 1;                                           //0x31a
            UCHAR FreezeNormal : 1;                                           //0x31a
            UCHAR FreezeDeep : 1;                                             //0x31a
        };
    };
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    VOID* Spare22;                                                          //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
    UCHAR PriorityFloorCounts[32];                                          //0x338
    ULONG PriorityFloorSummary;                                             //0x358
    volatile LONG AbCompletedIoBoostCount;                                  //0x35c
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
    volatile SHORT KeReferenceCount;                                        //0x364
    UCHAR AbOrphanedEntrySummary;                                           //0x366
    UCHAR AbOwnedEntryCount;                                                //0x367
    ULONG ForegroundLossTime;                                               //0x368
    union
    {
        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x370
        struct
        {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
            ULONGLONG InGlobalForegroundList;                               //0x378
        };
    };
    LONGLONG ReadOperationCount;                                            //0x380
    LONGLONG WriteOperationCount;                                           //0x388
    LONGLONG OtherOperationCount;                                           //0x390
    LONGLONG ReadTransferCount;                                             //0x398
    LONGLONG WriteTransferCount;                                            //0x3a0
    LONGLONG OtherTransferCount;                                            //0x3a8
    struct _KSCB* QueuedScb;                                                //0x3b0
    volatile ULONG ThreadTimerDelay;                                        //0x3b8
    union
    {
        volatile LONG ThreadFlags3;                                         //0x3bc
        struct
        {
            ULONG ThreadFlags3Reserved : 8;                                   //0x3bc
            ULONG PpmPolicy : 3;                                              //0x3bc
            ULONG ThreadFlags3Reserved2 : 21;                                 //0x3bc
        };
    };
    ULONGLONG TracingPrivate[1];                                            //0x3c0
    VOID* SchedulerAssist;                                                  //0x3c8
    VOID* volatile AbWaitObject;                                            //0x3d0
    ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
    ULONGLONG KernelWaitTime;                                               //0x3e0
    ULONGLONG UserWaitTime;                                                 //0x3e8
    union
    {
        struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
        struct
        {
            struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
            ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
        };
    };
    LONG SchedulerAssistPriorityFloor;                                      //0x400
    LONG RealtimePriorityFloor;                                             //0x404
    VOID* KernelShadowStack;                                                //0x408
    VOID* KernelShadowStackInitial;                                         //0x410
    VOID* KernelShadowStackBase;                                            //0x418
    void * KernelShadowStackLimit;                                          //0x420
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x428
    ULONGLONG HgsFeedbackStartTime;                                         //0x430
    ULONGLONG HgsFeedbackCycles;                                            //0x438
    ULONG HgsInvalidFeedbackCount;                                          //0x440
    ULONG HgsLowerPerfClassFeedbackCount;                                   //0x444
    ULONG HgsHigherPerfClassFeedbackCount;                                  //0x448
    ULONG Spare27;                                                          //0x44c
    struct _SINGLE_LIST_ENTRY SystemAffinityTokenListHead;                  //0x450
    VOID* IptSaveArea;                                                      //0x458
    UCHAR ResourceIndex;                                                    //0x460
    UCHAR CoreIsolationReasons;                                             //0x461
    UCHAR BamQosLevelFromAssistPage;                                        //0x462
    UCHAR Spare31[1];                                                       //0x463
    ULONG Spare32;                                                          //0x464
    ULONGLONG EndPadding[3];                                                //0x468
};