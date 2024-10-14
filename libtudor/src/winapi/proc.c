#include <asm/prctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "internal.h"

static struct {
    ULONG alloc_size;
    ULONG size;
    ULONG flags;
    ULONG debug_flags;
    //...
} process_params;

static struct {
    BOOLEAN inherited_addr_space, read_img_file_exec_opts, being_debugged, __pad1;
    HANDLE mutant;
    void *image_base_addr;
    void *peb_ldr_data;
    void *proc_params;
    void *sub_sys_data;
    HANDLE proc_heap;
    //...
} process_peb;

static __thread struct {
    void *cur_seh_frame;
    void *stack_base, *stack_limit;
    void *sub_system_tib, *fiber_data;
    void *arbitrary_data;
    void *teb_address;

    void *env_ptr;
    uintptr_t proc_id, thread_id;
    void *active_rpc;
    void *thread_local_storage;
    void *peb_ptr;
    //...
} thread_tib;

__constr static void init_peb() {
    //TODO This is incredibly hacky and crude

    //Initialize the process parameters
    process_params.alloc_size = 0;
    process_params.size = 0;
    process_params.flags = 0;
    process_params.debug_flags = 0;

    //Initialize the Process Environment Block
    process_peb.inherited_addr_space = FALSE;
    process_peb.read_img_file_exec_opts = TRUE;
    process_peb.being_debugged = FALSE;
    process_peb.mutant = (HANDLE) 0xdeadc0de;
    process_peb.image_base_addr = (void*) 0xdeadc0de;
    process_peb.peb_ldr_data = (void*) 0xdeadc0de;
    process_peb.proc_params = &process_params;
    process_peb.sub_sys_data = (void*) 0xdeadc0de;
    process_peb.proc_heap = (HANDLE) -1;
}

__constr void win_init_tib() {
    //TODO This is incredibly hacky and crude

    //Initialize the Thread Information Block
    thread_tib.cur_seh_frame = (void*) 0xdeadc0de;
    thread_tib.stack_base = (void*) 0xdeadc0de;
    thread_tib.stack_limit = (void*) 0xdeadc0de;
    thread_tib.sub_system_tib = (void*) 0xdeadc0de;
    thread_tib.fiber_data = (void*) 0xdeadc0de;
    thread_tib.arbitrary_data = (void*) 0xdeadc0de;
    thread_tib.teb_address = (void*) 0xdeadc0de;

    thread_tib.env_ptr = (void*) 0xdeadc0de;
    thread_tib.proc_id = getpid();
    thread_tib.thread_id = win_get_thread_id();
    thread_tib.active_rpc = (void*) 0xdeadc0de;
    thread_tib.thread_local_storage = (void*) 0xdeadc0de;
    thread_tib.peb_ptr = &process_peb;
    syscall(SYS_arch_prctl, ARCH_SET_GS, &thread_tib);
}

DWORD win_get_thread_id() { return (DWORD) syscall(__NR_gettid); }

__winfnc HANDLE GetCurrentProcess() {
    return (HANDLE) -1;
}
WINAPI(GetCurrentProcess)

__winfnc DWORD GetCurrentProcessId() {
    return getpid();
}
WINAPI(GetCurrentProcessId)

__winfnc DWORD GetCurrentThreadId() {
    return win_get_thread_id();
}
WINAPI(GetCurrentThreadId)

__winfnc BOOL TerminateProcess(HANDLE proc, UINT exit_code) {
    if(proc != (HANDLE) -1) return FALSE;
    log_error("TerminateProcess called with exit code 0x%x!", exit_code);
    abort();
}
WINAPI(TerminateProcess)

__winfnc HANDLE GetCurrentThread() {
    log_warn("GetCurrentThread: Called");

    return NULL;
}
WINAPI(GetCurrentThread)

extern __winfnc DWORD GetTickCount();

ULONG RtlUniform( ULONG *seed )
{
/* See the tests for details. */
return (*seed = ((ULONGLONG)*seed * 0x7fffffed + 0x7fffffc3) % 0x7fffffff);
}

static void * InterlockedCompareExchangePointer( void *volatile *dest, void *xchg, void *compare )
{
    return __sync_val_compare_and_swap( dest, compare, xchg );
}
static DWORD_PTR get_pointer_obfuscator( void )
{
    static DWORD_PTR pointer_obfuscator;

    if (!pointer_obfuscator)
    {
        ULONG seed = GetTickCount();
        ULONG_PTR rand;

        /* generate a random value for the obfuscator */
        rand = RtlUniform( &seed );

        /* handle 64bit pointers */
        rand ^= (ULONG_PTR)RtlUniform( &seed ) << ((sizeof (DWORD_PTR) - sizeof (ULONG))*8);

        /* set the high bits so dereferencing obfuscated pointers will (usually) crash */
        rand |= (ULONG_PTR)0xc0000000 << ((sizeof (DWORD_PTR) - sizeof (ULONG))*8);

        InterlockedCompareExchangePointer( (void**) &pointer_obfuscator, (void*) rand, NULL );
    }

    return pointer_obfuscator;
}

__winfnc PVOID EncodePointer(PVOID Ptr) {
    log_debug("Stub EncodePointer called!");
//    DWORD_PTR ptrval = (DWORD_PTR) Ptr;
//    return (PVOID)((DWORD)ptrval ^ (DWORD)get_pointer_obfuscator());
    return Ptr;
}
WINAPI(EncodePointer)

__winfnc void FlushProcessWriteBuffers() {
    log_warn("FlushProcessWriteBuffers: Called");
}
WINAPI(FlushProcessWriteBuffers)

__winfnc void FreeLibraryWhenCallbackReturns() {
    log_warn("FreeLibraryWhenCallbackReturns: Called");
}
WINAPI(FreeLibraryWhenCallbackReturns)

__winfnc void GetCurrentProcessorNumber() {
    log_warn("GetCurrentProcessorNumber: Called");
}
WINAPI(GetCurrentProcessorNumber)

__winfnc void GetLogicalProcessorInformation() {
    log_warn("GetLogicalProcessorInformation: Called");
}
WINAPI(GetLogicalProcessorInformation)

__winfnc void CreateSymbolicLinkW() {
    log_warn("CreateSymbolicLinkW: Called");
}
WINAPI(CreateSymbolicLinkW)

__winfnc void SetDefaultDllDirectories() {
    log_warn("SetDefaultDllDirectories: Called");
}
WINAPI(SetDefaultDllDirectories)

__winfnc void EnumSystemLocalesEx() {
    log_warn("EnumSystemLocalesEx: Called");
}
WINAPI(EnumSystemLocalesEx)

__winfnc void CompareStringEx() {
    log_warn("CompareStringEx: Called");
}
WINAPI(CompareStringEx)

__winfnc void GetDateFormatEx() {
    log_warn("GetDateFormatEx: Called");
}
WINAPI(GetDateFormatEx)

__winfnc void GetLocaleInfoEx() {
    log_warn("GetLocaleInfoEx: Called");
}
WINAPI(GetLocaleInfoEx)

__winfnc void GetTimeFormatEx() {
    log_warn("GetTimeFormatEx: Called");
}
WINAPI(GetTimeFormatEx)

__winfnc void GetUserDefaultLocaleName() {
    log_warn("GetUserDefaultLocaleName: Called");
}
WINAPI(GetUserDefaultLocaleName)

__winfnc void IsValidLocaleName() {
    log_warn("IsValidLocaleName: Called");
}
WINAPI(IsValidLocaleName)

__winfnc void GetCurrentPackageId() {
    log_warn("GetCurrentPackageId: Called");
}
WINAPI(GetCurrentPackageId)

__winfnc void GetFileInformationByHandleExW() {
    log_warn("GetFileInformationByHandleExW: Called");
}
WINAPI(GetFileInformationByHandleExW)

__winfnc void SetFileInformationByHandleW() {
    log_warn("SetFileInformationByHandleW: Called");
}
WINAPI(SetFileInformationByHandleW)

__winfnc void ExitProcess(UINT exitCode) {
    log_warn("ExitProcess: Called");
}
WINAPI(ExitProcess)

__winfnc void GetFileType() {
     log_warn("GetFileType: Called");
}

WINAPI(GetFileType)

__winfnc void RtlVirtualUnwind() {
     log_warn("RtlVirtualUnwind: Called");
}

WINAPI(RtlVirtualUnwind)

__winfnc void CreateSemaphoreW() {
     log_warn("CreateSemaphoreW: Called");
}

WINAPI(CreateSemaphoreW)

__winfnc void RtlUnwindEx() {
     log_warn("RtlUnwindEx: Called");
}

WINAPI(RtlUnwindEx)

__winfnc void GetOEMCP() {
     log_warn("GetOEMCP: Called");
}

WINAPI(GetOEMCP)

__winfnc void FatalAppExitA() {
     log_warn("FatalAppExitA: Called");
}

WINAPI(FatalAppExitA)

__winfnc void SetConsoleCtrlHandler() {
     log_warn("SetConsoleCtrlHandler: Called");
}

WINAPI(SetConsoleCtrlHandler)

__winfnc void HeapReAlloc() {
     log_warn("HeapReAlloc: Called");
}

WINAPI(HeapReAlloc)

__winfnc void GetDateFormatW() {
     log_warn("GetDateFormatW: Called");
}

WINAPI(GetDateFormatW)

__winfnc void GetTimeFormatW() {
     log_warn("GetTimeFormatW: Called");
}

WINAPI(GetTimeFormatW)

__winfnc void CompareStringW() {
     log_warn("CompareStringW: Called");
}

WINAPI(CompareStringW)

__winfnc void GetLocaleInfoW() {
     log_warn("GetLocaleInfoW: Called");
}

WINAPI(GetLocaleInfoW)

__winfnc void IsValidLocale() {
     log_warn("IsValidLocale: Called");
}

WINAPI(IsValidLocale)

__winfnc void GetUserDefaultLCID() {
     log_warn("GetUserDefaultLCID: Called");
}

WINAPI(GetUserDefaultLCID)

__winfnc void EnumSystemLocalesW() {
     log_warn("EnumSystemLocalesW: Called");
}

WINAPI(EnumSystemLocalesW)

__winfnc void OutputDebugStringW() {
     log_warn("OutputDebugStringW: Called");
}

WINAPI(OutputDebugStringW)

__winfnc void RaiseException() {
     log_warn("RaiseException: Called");
}

WINAPI(RaiseException)

__winfnc void HeapSize() {
     log_warn("HeapSize: Called");
}

WINAPI(HeapSize)

__winfnc void FlushFileBuffers() {
     log_warn("FlushFileBuffers: Called");
}

WINAPI(FlushFileBuffers)

__winfnc void GetConsoleCP() {
     log_warn("GetConsoleCP: Called");
}

WINAPI(GetConsoleCP)

__winfnc void GetConsoleMode() {
     log_warn("GetConsoleMode: Called");
}

WINAPI(GetConsoleMode)

__winfnc void SetStdHandle() {
     log_warn("SetStdHandle: Called");
}

WINAPI(SetStdHandle)

__winfnc void SetFilePointerEx() {
     log_warn("SetFilePointerEx: Called");
}

WINAPI(SetFilePointerEx)

__winfnc void WriteConsoleW() {
     log_warn("WriteConsoleW: Called");
}

WINAPI(WriteConsoleW)

__winfnc void CreateFileW() {
     log_warn("CreateFileW: Called");
}

WINAPI(CreateFileW)

__winfnc void GetTraceEnableFlags() {
     log_warn("GetTraceEnableFlags: Called");
}

WINAPI(GetTraceEnableFlags)

__winfnc void GetTraceEnableLevel() {
     log_warn("GetTraceEnableLevel: Called");
}

WINAPI(GetTraceEnableLevel)

__winfnc void GetTraceLoggerHandle() {
     log_warn("GetTraceLoggerHandle: Called");
}

WINAPI(GetTraceLoggerHandle)

__winfnc void WTSRegisterSessionNotification() {
     log_warn("WTSRegisterSessionNotification: Called");
}

WINAPI(WTSRegisterSessionNotification)

__winfnc void WTSUnRegisterSessionNotification() {
     log_warn("WTSUnRegisterSessionNotification: Called");
}

WINAPI(WTSUnRegisterSessionNotification)

__winfnc void Process32NextW() {
     log_warn("Process32NextW: Called");
}

WINAPI(Process32NextW)

__winfnc void Process32FirstW() {
     log_warn("Process32FirstW: Called");
}

WINAPI(Process32FirstW)

__winfnc void CreateToolhelp32Snapshot() {
     log_warn("CreateToolhelp32Snapshot: Called");
}

WINAPI(CreateToolhelp32Snapshot)

__winfnc void TerminateThread() {
     log_warn("TerminateThread: Called");
}

WINAPI(TerminateThread)

__winfnc void lstrcmpA() {
     log_warn("lstrcmpA: Called");
}

WINAPI(lstrcmpA)

__winfnc void OpenEventA() {
     log_warn("OpenEventA: Called");
}

WINAPI(OpenEventA)

__winfnc void OutputDebugStringA() {
     log_warn("OutputDebugStringA: Called");
}

WINAPI(OutputDebugStringA)

__winfnc void QueryPerformanceFrequency() {
     log_warn("QueryPerformanceFrequency: Called");
}

WINAPI(QueryPerformanceFrequency)

__winfnc void K32GetModuleFileNameExA() {
     log_warn("K32GetModuleFileNameExA: Called");
}

WINAPI(K32GetModuleFileNameExA)

__winfnc void CompareFileTime() {
     log_warn("CompareFileTime: Called");
}

WINAPI(CompareFileTime)

__winfnc void CreateDirectoryA() {
     log_warn("CreateDirectoryA: Called");
}

WINAPI(CreateDirectoryA)

__winfnc void FindClose() {
     log_warn("FindClose: Called");
}

WINAPI(FindClose)

__winfnc void FindFirstFileA() {
     log_warn("FindFirstFileA: Called");
}

WINAPI(FindFirstFileA)

__winfnc void FindNextFileA() {
     log_warn("FindNextFileA: Called");
}

WINAPI(FindNextFileA)

__winfnc void GetLocalTime() {
     log_warn("GetLocalTime: Called");
}

WINAPI(GetLocalTime)

__winfnc void VerifyVersionInfoA() {
     log_warn("VerifyVersionInfoA: Called");
}

WINAPI(VerifyVersionInfoA)

__winfnc void GetCurrentDirectoryA() {
     log_warn("GetCurrentDirectoryA: Called");
}

WINAPI(GetCurrentDirectoryA)

__winfnc void LoadLibraryA() {
     log_warn("LoadLibraryA: Called");
}

WINAPI(LoadLibraryA)

__winfnc void ReleaseSemaphore() {
     log_warn("ReleaseSemaphore: Called");
}

WINAPI(ReleaseSemaphore)

__winfnc void ReleaseMutex() {
     log_warn("ReleaseMutex: Called");
}

WINAPI(ReleaseMutex)

__winfnc void CreateMutexA() {
     log_warn("CreateMutexA: Called");
}

WINAPI(CreateMutexA)

__winfnc void GetProcessVersion() {
     log_warn("GetProcessVersion: Called");
}

WINAPI(GetProcessVersion)

__winfnc void CreateSemaphoreA() {
     log_warn("CreateSemaphoreA: Called");
}

WINAPI(CreateSemaphoreA)

__winfnc void OpenSemaphoreA() {
     log_warn("OpenSemaphoreA: Called");
}

WINAPI(OpenSemaphoreA)

__winfnc void K32GetProcessImageFileNameA() {
     log_warn("K32GetProcessImageFileNameA: Called");
}

WINAPI(K32GetProcessImageFileNameA)

__winfnc void CreateFileA() {
     log_warn("CreateFileA: Called");
}

WINAPI(CreateFileA)

__winfnc void CancelIo() {
     log_warn("CancelIo: Called");
}

WINAPI(CancelIo)

__winfnc void GetNumberOfConsoleInputEvents() {
     log_warn("GetNumberOfConsoleInputEvents: Called");
}

WINAPI(GetNumberOfConsoleInputEvents)

__winfnc void PeekConsoleInputA() {
     log_warn("PeekConsoleInputA: Called");
}

WINAPI(PeekConsoleInputA)

__winfnc void ReadConsoleInputA() {
     log_warn("ReadConsoleInputA: Called");
}

WINAPI(ReadConsoleInputA)

__winfnc void SetConsoleMode() {
     log_warn("SetConsoleMode: Called");
}

WINAPI(SetConsoleMode)

__winfnc void RtlPcToFileHeader() {
     log_warn("RtlPcToFileHeader: Called");
}

WINAPI(RtlPcToFileHeader)

__winfnc void ReadConsoleW() {
     log_warn("ReadConsoleW: Called");
}

WINAPI(ReadConsoleW)

__winfnc void GetTimeZoneInformation() {
     log_warn("GetTimeZoneInformation: Called");
}

WINAPI(GetTimeZoneInformation)

__winfnc void DeleteFileW() {
     log_warn("DeleteFileW: Called");
}

WINAPI(DeleteFileW)

__winfnc void MoveFileExW() {
     log_warn("MoveFileExW: Called");
}

WINAPI(MoveFileExW)

__winfnc void SetEnvironmentVariableA() {
     log_warn("SetEnvironmentVariableA: Called");
}

WINAPI(SetEnvironmentVariableA)

__winfnc void SetEndOfFile() {
     log_warn("SetEndOfFile: Called");
}

WINAPI(SetEndOfFile)

__winfnc void OpenProcess() {
     log_warn("OpenProcess: Called");
}

WINAPI(OpenProcess)

__winfnc void TraceEvent() {
     log_warn("TraceEvent: Called");
}

WINAPI(TraceEvent)

__winfnc void EnableTrace() {
     log_warn("EnableTrace: Called");
}

WINAPI(EnableTrace)

__winfnc void ControlTraceA() {
     log_warn("ControlTraceA: Called");
}

WINAPI(ControlTraceA)

__winfnc void StartTraceA() {
     log_warn("StartTraceA: Called");
}

WINAPI(StartTraceA)

__winfnc void ReportEventA() {
     log_warn("ReportEventA: Called");
}

WINAPI(ReportEventA)

__winfnc void RegisterEventSourceA() {
     log_warn("RegisterEventSourceA: Called");
}

WINAPI(RegisterEventSourceA)

__winfnc void DeregisterEventSource() {
     log_warn("DeregisterEventSource: Called");
}

WINAPI(DeregisterEventSource)

__winfnc void QueryServiceConfigA() {
     log_warn("QueryServiceConfigA: Called");
}

WINAPI(QueryServiceConfigA)

__winfnc void OpenServiceA() {
     log_warn("OpenServiceA: Called");
}

WINAPI(OpenServiceA)

__winfnc void OpenSCManagerA() {
     log_warn("OpenSCManagerA: Called");
}

WINAPI(OpenSCManagerA)

__winfnc void CloseServiceHandle() {
     log_warn("CloseServiceHandle: Called");
}

WINAPI(CloseServiceHandle)

__winfnc void SetEntriesInAclA() {
     log_warn("SetEntriesInAclA: Called");
}

WINAPI(SetEntriesInAclA)

__winfnc void SetSecurityDescriptorDacl() {
     log_warn("SetSecurityDescriptorDacl: Called");
}

WINAPI(SetSecurityDescriptorDacl)

__winfnc void CryptGenKey() {
     log_warn("CryptGenKey: Called");
}

WINAPI(CryptGenKey)

__winfnc void CryptSetKeyParam() {
     log_warn("CryptSetKeyParam: Called");
}

WINAPI(CryptSetKeyParam)

__winfnc void CryptExportKey() {
     log_warn("CryptExportKey: Called");
}

WINAPI(CryptExportKey)

__winfnc void CryptEncrypt() {
     log_warn("CryptEncrypt: Called");
}

WINAPI(CryptEncrypt)

__winfnc void CryptDecrypt() {
     log_warn("CryptDecrypt: Called");
}

WINAPI(CryptDecrypt)

__winfnc void CryptSignHashA() {
     log_warn("CryptSignHashA: Called");
}

WINAPI(CryptSignHashA)

__winfnc void CryptVerifySignatureA() {
     log_warn("CryptVerifySignatureA: Called");
}

WINAPI(CryptVerifySignatureA)

__winfnc void RegDeleteKeyA() {
     log_warn("RegDeleteKeyA: Called");
}

WINAPI(RegDeleteKeyA)

__winfnc void RegDeleteValueA() {
     log_warn("RegDeleteValueA: Called");
}

WINAPI(RegDeleteValueA)

__winfnc void RegEnumKeyExA() {
     log_warn("RegEnumKeyExA: Called");
}

WINAPI(RegEnumKeyExA)

__winfnc void RegEnumValueA() {
     log_warn("RegEnumValueA: Called");
}

WINAPI(RegEnumValueA)

__winfnc void RegQueryInfoKeyA() {
     log_warn("RegQueryInfoKeyA: Called");
}

WINAPI(RegQueryInfoKeyA)

__winfnc void InitializeSecurityDescriptor() {
     log_warn("InitializeSecurityDescriptor: Called");
}

WINAPI(InitializeSecurityDescriptor)

__winfnc void FreeSid() {
     log_warn("FreeSid: Called");
}

WINAPI(FreeSid)

__winfnc void AllocateAndInitializeSid() {
     log_warn("AllocateAndInitializeSid: Called");
}

WINAPI(AllocateAndInitializeSid)

__winfnc void CoCreateInstance() {
     log_warn("CoCreateInstance: Called");
}

WINAPI(CoCreateInstance)

__winfnc void BeginPaint() {
     log_warn("BeginPaint: Called");
}

WINAPI(BeginPaint)

__winfnc void EndPaint() {
     log_warn("EndPaint: Called");
}

WINAPI(EndPaint)

__winfnc void GetWindowLongPtrW() {
     log_warn("GetWindowLongPtrW: Called");
}

WINAPI(GetWindowLongPtrW)

__winfnc void SetWindowLongPtrW() {
     log_warn("SetWindowLongPtrW: Called");
}

WINAPI(SetWindowLongPtrW)

__winfnc void PeekMessageW() {
     log_warn("PeekMessageW: Called");
}

WINAPI(PeekMessageW)

__winfnc void PostMessageW() {
     log_warn("PostMessageW: Called");
}

WINAPI(PostMessageW)

__winfnc void RegisterPowerSettingNotification() {
     log_warn("RegisterPowerSettingNotification: Called");
}

WINAPI(RegisterPowerSettingNotification)

__winfnc void FindWindowW() {
     log_warn("FindWindowW: Called");
}

WINAPI(FindWindowW)

__winfnc void UnregisterPowerSettingNotification() {
     log_warn("UnregisterPowerSettingNotification: Called");
}

WINAPI(UnregisterPowerSettingNotification)

__winfnc void DefWindowProcW() {
     log_warn("DefWindowProcW: Called");
}

WINAPI(DefWindowProcW)

__winfnc void CallWindowProcW() {
     log_warn("CallWindowProcW: Called");
}

WINAPI(CallWindowProcW)

__winfnc void RegisterClassExW() {
     log_warn("RegisterClassExW: Called");
}

WINAPI(RegisterClassExW)

__winfnc void CreateWindowExW() {
     log_warn("CreateWindowExW: Called");
}

WINAPI(CreateWindowExW)

__winfnc void PostThreadMessageW() {
     log_warn("PostThreadMessageW: Called");
}

WINAPI(PostThreadMessageW)

__winfnc void DispatchMessageW() {
     log_warn("DispatchMessageW: Called");
}

WINAPI(DispatchMessageW)

__winfnc void TranslateMessage() {
     log_warn("TranslateMessage: Called");
}

WINAPI(TranslateMessage)

__winfnc void GetMessageW() {
     log_warn("GetMessageW: Called");
}

WINAPI(GetMessageW)

__winfnc void UnregisterClassW() {
     log_warn("UnregisterClassW: Called");
}

WINAPI(UnregisterClassW)

__winfnc void PostQuitMessage() {
     log_warn("PostQuitMessage: Called");
}

WINAPI(PostQuitMessage)

__winfnc void DestroyWindow() {
     log_warn("DestroyWindow: Called");
}

WINAPI(DestroyWindow)

__winfnc void SHCreateDirectoryExA() {
     log_warn("SHCreateDirectoryExA: Called");
}

WINAPI(SHCreateDirectoryExA)

__winfnc void SHFileOperationA() {
     log_warn("SHFileOperationA: Called");
}

WINAPI(SHFileOperationA)

__winfnc void SHGetFolderPathA() {
     log_warn("SHGetFolderPathA: Called");
}

WINAPI(SHGetFolderPathA)

__winfnc void PathAppendA() {
     log_warn("PathAppendA: Called");
}

WINAPI(PathAppendA)

__winfnc void PathFileExistsA() {
     log_warn("PathFileExistsA: Called");
}

WINAPI(PathFileExistsA)

__winfnc void UuidCreate() {
     log_warn("UuidCreate: Called");
}

WINAPI(UuidCreate)

__winfnc void SetupDiCallClassInstaller() {
     log_warn("SetupDiCallClassInstaller: Called");
}

WINAPI(SetupDiCallClassInstaller)

__winfnc void SetupDiSetClassInstallParamsA() {
     log_warn("SetupDiSetClassInstallParamsA: Called");
}

WINAPI(SetupDiSetClassInstallParamsA)

__winfnc void SetupDiGetDeviceInstallParamsA() {
     log_warn("SetupDiGetDeviceInstallParamsA: Called");
}

WINAPI(SetupDiGetDeviceInstallParamsA)

__winfnc void SetupDiGetDeviceRegistryPropertyA() {
     log_warn("SetupDiGetDeviceRegistryPropertyA: Called");
}

WINAPI(SetupDiGetDeviceRegistryPropertyA)

__winfnc void SetupDiOpenDeviceInterfaceA() {
     log_warn("SetupDiOpenDeviceInterfaceA: Called");
}

WINAPI(SetupDiOpenDeviceInterfaceA)

__winfnc void SetupDiDestroyDeviceInfoList() {
     log_warn("SetupDiDestroyDeviceInfoList: Called");
}

WINAPI(SetupDiDestroyDeviceInfoList)

__winfnc void SetupDiEnumDeviceInfo() {
     log_warn("SetupDiEnumDeviceInfo: Called");
}

WINAPI(SetupDiEnumDeviceInfo)

__winfnc void SetupDiCreateDeviceInfoList() {
     log_warn("SetupDiCreateDeviceInfoList: Called");
}

WINAPI(SetupDiCreateDeviceInfoList)

__winfnc void CM_Get_Parent() {
     log_warn("CM_Get_Parent: Called");
}

WINAPI(CM_Get_Parent)

__winfnc void CM_Get_DevNode_Registry_PropertyA() {
     log_warn("CM_Get_DevNode_Registry_PropertyA: Called");
}

WINAPI(CM_Get_DevNode_Registry_PropertyA)

__winfnc void SetupDiGetClassDevsA() {
     log_warn("SetupDiGetClassDevsA: Called");
}

WINAPI(SetupDiGetClassDevsA)

__winfnc void SetupDiGetDeviceInterfaceDetailA() {
     log_warn("SetupDiGetDeviceInterfaceDetailA: Called");
}

WINAPI(SetupDiGetDeviceInterfaceDetailA)

__winfnc void SetupDiEnumDeviceInterfaces() {
     log_warn("SetupDiEnumDeviceInterfaces: Called");
}

WINAPI(SetupDiEnumDeviceInterfaces)

__winfnc void HidD_GetHidGuid() {
     log_warn("HidD_GetHidGuid: Called");
}

WINAPI(HidD_GetHidGuid)

__winfnc void HidD_FreePreparsedData() {
     log_warn("HidD_FreePreparsedData: Called");
}

WINAPI(HidD_FreePreparsedData)

__winfnc void HidD_GetPreparsedData() {
     log_warn("HidD_GetPreparsedData: Called");
}

WINAPI(HidD_GetPreparsedData)

__winfnc void HidD_GetAttributes() {
     log_warn("HidD_GetAttributes: Called");
}

WINAPI(HidD_GetAttributes)

__winfnc void HidP_GetCaps() {
     log_warn("HidP_GetCaps: Called");
}

WINAPI(HidP_GetCaps)


typedef struct {
    DWORD cb;
    const char16_t *lpReserved;
    const char16_t *lpDesktop;
    const char16_t *lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    BYTE *lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW;

__winfnc void GetStartupInfoW(STARTUPINFOW *info) {
    static char16_t *desktop = NULL;
    if(!desktop) desktop = winstr_from_str("TUDORHOST");

    info->cb = sizeof(STARTUPINFOW);
    info->lpReserved = NULL;
    info->lpDesktop = desktop;
    info->lpTitle = NULL;
    info->dwX = info->dwY = 0;
    info->dwXSize = info->dwYSize = 0;
    info->dwXCountChars = info->dwYCountChars = 0;
    info->dwFillAttribute = 0;
    info->dwFlags = 0;
    info->wShowWindow = 0;
    info->cbReserved2 = 0;
    info->lpReserved2 = NULL;
    info->hStdInput = info->hStdOutput = info->hStdError = NULL;
}
WINAPI(GetStartupInfoW);

__winfnc const char *GetCommandLineA() {
    return winmodule_get_cur()->cmdline;
}
WINAPI(GetCommandLineA)

__winfnc const char16_t *GetCommandLineW() {
    static char16_t *cmd_line;
    if(!cmd_line) cmd_line = winstr_from_str(GetCommandLineA());
    return cmd_line;
}
WINAPI(GetCommandLineW)

__winfnc const char *GetEnvironmentStringsA() {
    //Determine environment block size
    int len = 1;
    for(const char **p = winmodule_get_cur()->environ; *p; p++) len += strlen(*p) + 1;

    //Create environment block
    char *env = (char*) malloc(len);
    if(!env) { winerr_set_errno(); return NULL; }

    char *d = env;
    for(const char **p = winmodule_get_cur()->environ; *p; p++) {
        int l = strlen(*p);
        memcpy(d, *p, l+1);
        d += l + 1;
    }
    *d = 0;

    return env;
}
WINAPI(GetEnvironmentStringsA)

__winfnc BOOL FreeEnvironmentStringsA(const char *env) {
    free((void*) env);
    return TRUE;
}
WINAPI(FreeEnvironmentStringsA)

__winfnc const char16_t *GetEnvironmentStringsW() {
    //Determine environment block size
    int len = 1;
    for(const char **p = winmodule_get_cur()->environ; *p; p++) len += strlen(*p) + 1;

    //Create environment block
    char16_t *env = (char16_t*) malloc(len * sizeof(char16_t));
    if(!env) { winerr_set_errno(); return NULL; }

    char16_t *d = env;
    for(const char **p = winmodule_get_cur()->environ; *p; p++) {
        char16_t *wp = winstr_from_str(*p);
        int l = winstr_len(wp);
        memcpy(d, *p, (l+1) * sizeof(char16_t));
        d += l + 1;
        free(wp);
    }
    *d = 0;

    return env;
}
WINAPI(GetEnvironmentStringsW)

__winfnc BOOL FreeEnvironmentStringsW(const char16_t *env) {
    free((void*) env);
    return TRUE;
}
WINAPI(FreeEnvironmentStringsW)

__winfnc BOOL IsProcessorFeaturePresent(DWORD feature) {
    log_debug("IsProcessorFeaturePresent | feature: %d", feature);
    return FALSE;
}
WINAPI(IsProcessorFeaturePresent)

#define ARM64_MAX_BREAKPOINTS 8
#define ARM64_MAX_WATCHPOINTS 2

typedef union {
    struct {
        ULONGLONG Low;
        LONGLONG High;
    } DUMMYSTRUCTNAME;
    double D[2];
    float S[4];
    WORD H[8];
    BYTE B[16];
} ARM64_NT_NEON128;

typedef struct {
    DWORD ContextFlags;
    DWORD Cpsr;
    union {
        struct {
            DWORD64 X0;
            DWORD64 X1;
            DWORD64 X2;
            DWORD64 X3;
            DWORD64 X4;
            DWORD64 X5;
            DWORD64 X6;
            DWORD64 X7;
            DWORD64 X8;
            DWORD64 X9;
            DWORD64 X10;
            DWORD64 X11;
            DWORD64 X12;
            DWORD64 X13;
            DWORD64 X14;
            DWORD64 X15;
            DWORD64 X16;
            DWORD64 X17;
            DWORD64 X18;
            DWORD64 X19;
            DWORD64 X20;
            DWORD64 X21;
            DWORD64 X22;
            DWORD64 X23;
            DWORD64 X24;
            DWORD64 X25;
            DWORD64 X26;
            DWORD64 X27;
            DWORD64 X28;
            DWORD64 Fp;
            DWORD64 Lr;
        } DUMMYSTRUCTNAME;
        DWORD64 X[31];
    } DUMMYUNIONNAME;
    DWORD64 Sp;
    DWORD64 Pc;
    ARM64_NT_NEON128 V[32];
    DWORD Fpcr;
    DWORD Fpsr;
    DWORD Bcr[ARM64_MAX_BREAKPOINTS];
    DWORD64 Bvr[ARM64_MAX_BREAKPOINTS];
    DWORD Wcr[ARM64_MAX_WATCHPOINTS];
    DWORD64 Wvr[ARM64_MAX_WATCHPOINTS];
} ARM64_NT_CONTEXT;

__winfnc void RtlCaptureContext(ARM64_NT_CONTEXT *context) {
    log_warn("Unsupported function RtlCaptureContext called!");
    *context = (ARM64_NT_CONTEXT) {0};
}
WINAPI(RtlCaptureContext)

__winfnc void *RtlLookupFunctionEntry(DWORD64 pc, DWORD64 *image_base, void *history) {
    return NULL;
}
WINAPI(RtlLookupFunctionEntry)

__winfnc BOOL IsDebuggerPresent() {
    return FALSE;
}
WINAPI(IsDebuggerPresent)

typedef LONG __winfnc TOP_LEVEL_EXCEPTION_FILTER(void *ExceptionPointers);

static TOP_LEVEL_EXCEPTION_FILTER *excep_filter = NULL;

__winfnc TOP_LEVEL_EXCEPTION_FILTER *SetUnhandledExceptionFilter(TOP_LEVEL_EXCEPTION_FILTER *filter) {
    TOP_LEVEL_EXCEPTION_FILTER *old_filter = excep_filter;
    excep_filter = filter;
    return old_filter;
}
WINAPI(SetUnhandledExceptionFilter)

__winfnc LONG UnhandledExceptionFilter(void *excep_pointers) {
    if(excep_filter) {
        LONG ret = excep_filter(excep_pointers);
        if(ret == 0 || ret == 1) return ret;
    }
    return 1;
}
WINAPI(UnhandledExceptionFilter)

__winfnc void Sleep(DWORD num_ms) {
    cant_fail(usleep((useconds_t) num_ms * 1000));
}
WINAPI(Sleep)