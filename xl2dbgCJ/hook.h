#pragma once

using namespace std;

class hook
{
public:
    static hook& getInstance();
    hook(const hook&) = delete;
    hook& operator=(const hook&) = delete;
private:
    hook();

private:
    
public:
	static hook* _This;

public:
    int startHook();
    int exitHook();

    static bool loadDriver();
    static bool unloadDriver();

private:
	void* _Original_ReadVirtualMemory = nullptr;
	void* _Original_WriteVirtualMemory = nullptr;
	void* _Original_NtOpenProcess = nullptr;
	void* _Original_NtCreateDebugObject = nullptr;
	void* _Original_DebugActiveProcess = nullptr;	// qd
	void* _Original_NtDebugActiveProcess = nullptr;
	void* _Original_NtRemoveProcessDebug = nullptr;
	void* _Original_DbgUiWaitStateChange = nullptr;	// qd
	void* _Original_NtWaitForDebugEvent = nullptr;	//new
	void* _Original_DbgUiContinue = nullptr;	// qd
	void* _Original_NtDebugContinue = nullptr;	// new
	void* _Original_DbgUiGetThreadDebugObject = nullptr;
	void* _Original_DbgUiConnectToDbg = nullptr;	// qd
	void* _Original_DbgUiDebugActiveProcess = nullptr;	// qd

	void* _Original_DbgUiIssueRemoteBreakin = nullptr;

public:
	static NTSTATUS NTAPI NewNtWriteVirtualMemory(
		IN  HANDLE ProcessHandle,
		OUT PVOID BaseAddress,
		IN  PVOID Buffer,
		IN  SIZE_T BufferSize,
		OUT PSIZE_T NumberOfBytesWritten OPTIONAL);
	static NTSTATUS NTAPI NewNtReadVirtualMemory(
		_In_ HANDLE  ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_Out_bytecap_(BufferBytes) PVOID Buffer,
		_In_ SIZE_T BufferBytes,
		_Out_opt_ PSIZE_T ReturnBytes);
	static NTSTATUS NTAPI NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory* temp_message);
    static NTSTATUS NTAPI NewNtOpenProcess(
        OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN OPTIONAL PCLIENT_ID ClientId);
    static NTSTATUS NTAPI NewNtCreateDebugObject(
        OUT PHANDLE DebugObjectHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN ULONG Flags);
	static BOOL NTAPI NewDebugActiveProcess(DWORD dwProcessId);
	static NTSTATUS NTAPI NewNtDebugActiveProcess(
		IN HANDLE ProcessHandle,
		IN HANDLE DebugObjectHandle);
    static NTSTATUS NTAPI NewNtRemoveProcessDebug(
        IN HANDLE ProcessHandle,
        IN HANDLE DebugObjectHandle);
public:
	static NTSTATUS NTAPI NewDbgUiWaitStateChange(
		OUT PDBGUI_WAIT_STATE_CHANGE StateChange,
		IN PLARGE_INTEGER Timeout OPTIONAL);
	static NTSTATUS NTAPI NewNtWaitForDebugEvent(
		IN HANDLE DebugObjectHandle,
		IN BOOLEAN Alertable,
		IN OPTIONAL PLARGE_INTEGER Timeout,
		OUT PVOID pStateChange);
	static NTSTATUS NTAPI NewDbgUiContinue(
		IN PCLIENT_ID AppClientId,
		IN NTSTATUS ContinueStatus);
	static NTSTATUS NewNtDebugContinue(
		IN HANDLE DebugObjectHandle,
		IN PCLIENT_ID ClientId,
		IN NTSTATUS ContinueStatus);
	static HANDLE NTAPI NewDbgUiGetThreadDebugObject();
	static NTSTATUS WINAPI NewDbgUiConnectToDbg(VOID);
	static NTSTATUS NTAPI NewDbgUiDebugActiveProcess(IN HANDLE Process);
	static NTSTATUS NTAPI NewDbgUiIssueRemoteBreakin(IN HANDLE processHandle);
private:
    static HANDLE _DebugObjectHandle;
};

