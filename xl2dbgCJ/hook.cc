#pragma once
#include "pch.h"

#include "hook.h"

hook* hook::_This = nullptr;

hook& hook::getInstance()
{
	static hook instance;
	return instance;
}
hook::hook()
{
	_This = this;
}

ScmDrvCtrl& dc = ScmDrvCtrl::getInstance();

HANDLE hook::_DebugObjectHandle = nullptr;

bool hook::loadDriver()
{
	bool b;
	char msg[256] = { 0 };

	ScmDrvCtrl* dc = ScmDrvCtrl::getInstance()._This;
	const char* sysFileName = "xl2kerneldbg.sys";
	//设置驱动名称
	char filePath[MAX_PATH] = { 0 };
	dc->GetAppPath(filePath);
	strcat_s(filePath, sysFileName);
	dc->m_pSysPath = filePath;
	dc->m_pDisplayName = "xl2kerneldbg";
	dc->m_pServiceName = "xl2kerneldbg";
	dc->pLinkName = "\\\\.\\xl2kerneldbg";

	//安装并启动驱动
	b = dc->Install();
	cout << "driver install b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
	//system("pause");
	if (!b)
	{
	    sprintf_s(msg, "Driver Install fail, code:%x", GetLastError());
	    MessageBoxA(0, msg, "err", 0);
		return false;
	}
	b = dc->Start();
	cout << "driver Start b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
	//system("pause");
	if (!b)
	{
	    sprintf_s(msg, "Driver Start fail, code:%x", GetLastError());
	    MessageBoxA(0, msg, "err", 0);
		return false;
	}
	printf("LoadDriver=%d\n", b);

	b = dc->Open();
	cout << "driver open b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;

	return true;
}
bool hook::unloadDriver()
{
	bool b;
	ScmDrvCtrl* dc = ScmDrvCtrl::getInstance()._This;

	b = CloseHandle(dc->m_hDriver);
	cout << "driver close b:" << b << endl;
	//system("pause");


	b = dc->Stop();
	cout << "driver stop b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
	//system("pause");

	b = dc->Remove();
	cout << "driver remove b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
	//system("pause");

	cout << "unloadDriver called b:" << b << endl;

	return true;
}

int hook::startHook()
{


	cout << "call startHook()" << endl;
	int ret = DetourTransactionBegin();
	if (ret != NO_ERROR)
	{
		cout << "[DetoursDemo]DetourTransactionBegin() fail.." << endl;
		return -1;
	}

	cout << "[DetoursDemo]DetourTransactionBegin() ok.." << endl;

	ret = DetourUpdateThread(GetCurrentThread());
	if (ret != NO_ERROR)
	{
		cout << "[DetoursDemo]DetourUpdateThread(GetCurrentThread()) fail..=========>GetCurrentThread()" << GetCurrentThread() << endl;
		return -2;
	}
	cout << "[DetoursDemo]DetourUpdateThread(GetCurrentThread()) ok.." << endl;


	//_Original_ReadVirtualMemory = DetourFindFunction("Ntdll.dll", "NtReadVirtualMemory");
	//ret = DetourAttach(&_Original_ReadVirtualMemory, NewNtReadVirtualMemory);
	//if (ret != NO_ERROR)
	//{
	//	return 9;
	//}

	//_Original_WriteVirtualMemory = DetourFindFunction("Ntdll.dll", "NtWriteVirtualMemory");
	//ret = DetourAttach(&_Original_WriteVirtualMemory, NewNtWriteVirtualMemory);
	//if (ret != NO_ERROR)
	//{
	//	return 10;
	//}

	//_Original_NtOpenProcess = DetourFindFunction("Ntdll.dll", "NtOpenProcess");
	//ret = DetourAttach(&_Original_NtOpenProcess, NewNtOpenProcess);
	//if (ret != NO_ERROR)
	//{
	//	return 11;
	//}

	_Original_NtCreateDebugObject = DetourFindFunction("Ntdll.dll", "NtCreateDebugObject");
	ret = DetourAttach(&_Original_NtCreateDebugObject, NewNtCreateDebugObject);
	if (ret != NO_ERROR)
	{
		return 12;
	}

	//_Original_DebugActiveProcess = DetourFindFunction("kernel32.dll", "DebugActiveProcess");
	//ret = DetourAttach(&_Original_DebugActiveProcess, NewDebugActiveProcess);
	//if (ret != NO_ERROR)
	//{
	//	return 13;
	//}

	_Original_NtDebugActiveProcess = DetourFindFunction("Ntdll.dll", "NtDebugActiveProcess");
	ret = DetourAttach(&_Original_NtDebugActiveProcess, NewNtDebugActiveProcess);
	if (ret != NO_ERROR)
	{
		return 14;
	}


	//_Original_NtRemoveProcessDebug = DetourFindFunction("Ntdll.dll", "NtRemoveProcessDebug");
	//ret = DetourAttach(&_Original_NtRemoveProcessDebug, NewNtRemoveProcessDebug);
	//if (ret != NO_ERROR)
	//{
	//	return 15;
	//}

	//_Original_DbgUiWaitStateChange = DetourFindFunction("Ntdll.dll", "DbgUiWaitStateChange");
	//ret = DetourAttach(&_Original_DbgUiWaitStateChange, NewDbgUiWaitStateChange);
	//if (ret != NO_ERROR)
	//{
	//	return 16;
	//}

	_Original_NtWaitForDebugEvent = DetourFindFunction("Ntdll.dll", "NtWaitForDebugEvent");
	ret = DetourAttach(&_Original_NtWaitForDebugEvent, NewNtWaitForDebugEvent);
	if (ret != NO_ERROR)
	{
		return 21;
	}

	//_Original_DbgUiContinue = DetourFindFunction("Ntdll.dll", "DbgUiContinue");
	//ret = DetourAttach(&_Original_DbgUiContinue, NewDbgUiContinue);
	//if (ret != NO_ERROR)
	//{
	//	return 17;
	//}

	_Original_NtDebugContinue = DetourFindFunction("Ntdll.dll", "NtDebugContinue");
	ret = DetourAttach(&_Original_NtDebugContinue, NewNtDebugContinue);
	if (ret != NO_ERROR)
	{
		return 22;
	}

	_Original_DbgUiGetThreadDebugObject = DetourFindFunction("Ntdll.dll", "DbgUiGetThreadDebugObject");
	ret = DetourAttach(&_Original_DbgUiGetThreadDebugObject, NewDbgUiGetThreadDebugObject);
	if (ret != NO_ERROR)
	{
		return 18;
	}

	//_Original_DbgUiConnectToDbg = DetourFindFunction("Ntdll.dll", "DbgUiConnectToDbg");
	//ret = DetourAttach(&_Original_DbgUiConnectToDbg, NewDbgUiConnectToDbg);
	//if (ret != NO_ERROR)
	//{
	//	return 19;
	//}

	//_Original_DbgUiDebugActiveProcess = DetourFindFunction("Ntdll.dll", "DbgUiDebugActiveProcess");
	//ret = DetourAttach(&_Original_DbgUiDebugActiveProcess, NewDbgUiDebugActiveProcess);
	//if (ret != NO_ERROR)
	//{
	//	return 20;
	//}

	_Original_DbgUiIssueRemoteBreakin = DetourFindFunction("Ntdll.dll", "DbgUiIssueRemoteBreakin");
	ret = DetourAttach(&_Original_DbgUiIssueRemoteBreakin, NewDbgUiIssueRemoteBreakin);
	if (ret != NO_ERROR)
	{
		return 23;
	}

	ret = DetourTransactionCommit();
	if (ret != NO_ERROR)
	{
		cout << "[DetoursDemo]DetourTransactionCommit() fail===========>ret:" << ret << endl;
		return 3;
	}
	cout << "[DetoursDemo]DetourTransactionCommit() ok..." << endl;






	




	return 0;
}

int hook::exitHook()
{
	ULONG ret = 0;

	ret = DetourTransactionBegin();
	if (ret != NO_ERROR)
	{
		cout << "dll exit hook DetourTransactionBegin() error:" << ret << endl;
		return ret;
	}

	ret = DetourUpdateThread(GetCurrentThread());
	if (ret != NO_ERROR)
	{
		cout << "dll exit hook DetourUpdateThread(GetCurrentThread()) error:" << ret << endl;
		return ret;
	}

	if (_Original_ReadVirtualMemory) DetourDetach(&_Original_ReadVirtualMemory, NewNtReadVirtualMemory);
	if (_Original_WriteVirtualMemory) DetourDetach(&_Original_WriteVirtualMemory, NewNtWriteVirtualMemory);
	if (_Original_NtOpenProcess) DetourDetach(&_Original_NtOpenProcess, NewNtOpenProcess);
	if (_Original_NtCreateDebugObject) DetourDetach(&_Original_NtCreateDebugObject, NewNtCreateDebugObject);
	if (_Original_DebugActiveProcess) DetourDetach(&_Original_DebugActiveProcess, NewDebugActiveProcess);
	if (_Original_NtDebugActiveProcess) DetourDetach(&_Original_NtDebugActiveProcess, NewNtDebugActiveProcess);
	if (_Original_NtRemoveProcessDebug) DetourDetach(&_Original_NtRemoveProcessDebug, NewNtRemoveProcessDebug);
	if (_Original_DbgUiWaitStateChange) DetourDetach(&_Original_DbgUiWaitStateChange, NewDbgUiWaitStateChange);
	if (_Original_NtWaitForDebugEvent) DetourDetach(&_Original_NtWaitForDebugEvent, NewNtWaitForDebugEvent);
	if (_Original_DbgUiContinue) DetourDetach(&_Original_DbgUiContinue, NewDbgUiContinue);
	if (_Original_NtDebugContinue) DetourDetach(&_Original_NtDebugContinue, NewNtDebugContinue);
	if (_Original_DbgUiGetThreadDebugObject) DetourDetach(&_Original_DbgUiGetThreadDebugObject, NewDbgUiGetThreadDebugObject);
	if (_Original_DbgUiConnectToDbg) DetourDetach(&_Original_DbgUiConnectToDbg, NewDbgUiConnectToDbg);
	if (_Original_DbgUiDebugActiveProcess) DetourDetach(&_Original_DbgUiDebugActiveProcess, NewDbgUiDebugActiveProcess);
	if (_Original_DbgUiIssueRemoteBreakin) DetourDetach(&_Original_DbgUiIssueRemoteBreakin, NewDbgUiIssueRemoteBreakin);

	ret = DetourTransactionCommit();
	if (ret != NO_ERROR)
	{
		cout << "dll exit hook DetourTransactionCommit() error:" << ret << endl;
		return ret;
	}

	cout << "dll unhook over" << endl;

	unloadDriver();
	return true;
}

NTSTATUS NTAPI hook::NewNtWriteVirtualMemory(
	IN  HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN  PVOID Buffer,
	IN  SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
	Message_NtReadWriteVirtualMemory temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);
	temp_message.BaseAddress = BaseAddress;
	temp_message.Buffer = Buffer;
	temp_message.BufferBytes = BufferSize;
	temp_message.ReturnBytes = NumberOfBytesWritten;
	temp_message.Read = false;
	return NewNtReadWriteVirtualMemory(&temp_message);
}

NTSTATUS NTAPI hook::NewNtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_bytecap_(BufferBytes) PVOID Buffer,
	_In_ SIZE_T BufferBytes,
	_Out_opt_ PSIZE_T ReturnBytes)
{
	Message_NtReadWriteVirtualMemory temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);
	temp_message.BaseAddress = BaseAddress;
	temp_message.Buffer = Buffer;
	temp_message.BufferBytes = BufferBytes;
	temp_message.ReturnBytes = ReturnBytes;
	temp_message.Read = true;
	return NewNtReadWriteVirtualMemory(&temp_message);
}

NTSTATUS NTAPI hook::NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory* temp_message)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(dc.m_hDriver, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtReadWriteVirtualMemory,
		temp_message, sizeof(Message_NtReadWriteVirtualMemory),
		temp_message, sizeof(Message_NtReadWriteVirtualMemory));
	return status;
}

NTSTATUS NTAPI hook::NewNtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PCLIENT_ID ClientId)
{
	NTSTATUS status = 0;
	Message_NewNtOpenProcess temp_message = { 0 };
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DesiredAccess = DesiredAccess;
	temp_message.ObjectAttributes = ObjectAttributes;
	temp_message.ClientId = ClientId;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(dc.m_hDriver, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtOpenProcess,
		&temp_message, sizeof(Message_NewNtOpenProcess),
		&temp_message, sizeof(Message_NewNtOpenProcess));

	cout << "NewNtOpenProcess call ProcessHandle:" << hex << ProcessHandle
		<< ", DesiredAccess:" << hex << DesiredAccess
		<< ", ObjectAttributes:" << hex << ObjectAttributes
		<< ", ClientId->UniqueProcess:" << "0x" << hex << (ULONG64)ClientId->UniqueProcess << "," << dec << (ULONG64)(ClientId->UniqueProcess)
		<< endl;

	return status;
}

NTSTATUS NTAPI hook::NewNtCreateDebugObject(
	OUT PHANDLE pDebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	NTSTATUS status = 0;
#ifdef _AMD64_
	Message_NewNtCreateDebugObject temp_message = { 0 };
	temp_message.DebugObjectHandle = &_DebugObjectHandle; // pDebugObjectHandle;   &_DebugObjectHandle    obh1
	temp_message.DesiredAccess = DesiredAccess;
	temp_message.ObjectAttributes = ObjectAttributes;
	temp_message.Flags = Flags;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(ScmDrvCtrl::getInstance().m_hDriver, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtCreateDebugObject,
		&temp_message, sizeof(Message_NewNtCreateDebugObject),
		&temp_message, sizeof(Message_NewNtCreateDebugObject));

	//_DebugObjectHandle = *pDebugObjectHandle;

	cout << "NewNtCreateDebugObject called _DebugObjectHandle:" << hex << _DebugObjectHandle
		<< ", DesiredAccess:" << hex << DesiredAccess
		<< ", ObjectAttributes:" << hex << ObjectAttributes
		<< ", Flags:" << "0x" << hex << Flags
		<< ", status:" << "0x" << hex << status
		<< endl;

#else
	UNICODE_STRING64 temp_str = { 0 };//本就未初始化


	//Wow64ExtInit();
	//ULONG64 addr64 = VirtualAllocEx64(GetCurrentProcess(), NULL, sizeof(OBJECT_ATTRIBUTES64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//if (addr64 == 0)
	//{
	//	//MessageBoxA(NULL, NULL, NULL, NULL);
	//}

	OBJECT_ATTRIBUTES64 temp_obj = { 0 };
	temp_obj.Length = sizeof(OBJECT_ATTRIBUTES64);
	temp_obj.ObjectName = (ULONG64)ObjectAttributes->ObjectName;
	/*OBJECT_ATTRIBUTES64 *temp_obj = new OBJECT_ATTRIBUTES64();
	temp_obj->Length = sizeof(OBJECT_ATTRIBUTES64);*/


	Message_NewNtCreateDebugObject64 temp_message = { 0 };
	temp_message.DebugObjectHandle = (ULONG64)DebugObjectHandle;
	temp_message.DesiredAccess = DesiredAccess;
	temp_message.ObjectAttributes = (ULONG64)&temp_obj;
	temp_message.Flags = Flags;


	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtCreateDebugObject,
		&temp_message, sizeof(Message_NewNtCreateDebugObject64),
		&temp_message, sizeof(Message_NewNtCreateDebugObject64));


	ObjectAttributes->Attributes = temp_obj.Attributes;
	ObjectAttributes->Length = 0x18;
	ObjectAttributes->RootDirectory = (HANDLE)temp_obj.RootDirectory;
	ObjectAttributes->SecurityDescriptor = (PVOID)temp_obj.SecurityDescriptor;
	ObjectAttributes->SecurityQualityOfService = (PVOID)temp_obj.SecurityQualityOfService;
	/*if (temp_str.Buffer != 0)//未初始化
	{
		ObjectAttributes->ObjectName->Buffer = (PWSTR)temp_str.Buffer;
	}
	ObjectAttributes->ObjectName->Length = temp_str.Length;
	ObjectAttributes->ObjectName->MaximumLength = temp_str.MaximumLength;*/


#endif // _AMD64_


	return status;
}

BOOL NTAPI hook::NewDebugActiveProcess(DWORD dwProcessId)
{
	HANDLE Process;
	NTSTATUS Status;

	Status = NewDbgUiConnectToDbg();
	cout << "NewDbgUiConnectToDbg status:" << hex << Status << endl;
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	cout << "OpenProcess status:" << hex << Status << endl;
	if (Process == NULL)
	{
		return FALSE;
	}

	Status = NewDbgUiDebugActiveProcess(Process);
	cout << "NewDbgUiDebugActiveProcess status:" << hex << Status << endl;
	if (!NT_SUCCESS(Status))
	{
		NtClose(Process);
		return FALSE;
	}

	NtClose(Process);
	return TRUE;
}

NTSTATUS NTAPI hook::NewNtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	NTSTATUS status = 0;
#ifdef _AMD64_
	Message_NewNtDebugActiveProcess temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//DebugObjectHandle就是目标进程ID
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = _DebugObjectHandle; // obh6
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(ScmDrvCtrl::getInstance().m_hDriver, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtDebugActiveProcess,
		&temp_message, sizeof(Message_NewNtDebugActiveProcess),
		&temp_message, sizeof(Message_NewNtDebugActiveProcess));
#else
	Message_NewNtDebugActiveProcess64 temp_message = { 0 };
	temp_message.ProcessId = (ULONG64)GetProcessId(ProcessHandle);//DebugObjectHandle就是目标进程ID
	temp_message.ProcessHandle = (ULONG64)ProcessHandle;
	temp_message.DebugObjectHandle = (ULONG64)DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtDebugActiveProcess,
		&temp_message, sizeof(Message_NewNtDebugActiveProcess),
		&temp_message, sizeof(Message_NewNtDebugActiveProcess));
#endif // _AMD64_
	return status;
}

NTSTATUS NTAPI hook::NewNtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	NTSTATUS status = 0;
#ifdef _AMD64_
	Message_NewNtRemoveProcessDebug temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//同NewNtDebugActiveProcess
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(ScmDrvCtrl::getInstance().m_hDriver, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtRemoveProcessDebug,
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug),
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug));
#else
	Message_NewNtRemoveProcessDebug temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//同NewNtDebugActiveProcess
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtRemoveProcessDebug,
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug),
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug));
#endif // _AMD64_
	return status;
}


NTSTATUS WINAPI hook::NewDbgUiConnectToDbg(VOID)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa;
	//if (_DebugObjectHandle == nullptr)	// obh2..
	//{
	//	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	//	Status = NewNtCreateDebugObject(&_DebugObjectHandle, DEBUG_ALL_ACCESS, &oa, DEBUG_KILL_ON_CLOSE);
	//}

	/* Don't connect twice */
	if (NtCurrentTeb()->DbgSsReserved[1]) return STATUS_SUCCESS;

	/* Setup the Attributes */
	InitializeObjectAttributes(&oa, NULL, 0, NULL, 0);

	/* Create the object */
	return NewNtCreateDebugObject(&NtCurrentTeb()->DbgSsReserved[1],
		DEBUG_ALL_ACCESS,
		&oa,
		DEBUG_KILL_ON_CLOSE);

	return Status;
}

NTSTATUS NTAPI hook::NewDbgUiDebugActiveProcess(IN HANDLE Process)
{
	NTSTATUS Status;
	//Status = NewNtDebugActiveProcess(Process, _DebugObjectHandle);	// obh3
	//if (NT_SUCCESS(Status))
	//{
	//	Status = DbgUiIssueRemoteBreakin(Process);
	//	if (!NT_SUCCESS(Status))
	//	{
	//		Status = NewNtRemoveProcessDebug(Process, _DebugObjectHandle);//Status = DbgUiStopDebugging(Process);
	//	}
	//}

	cout << "start call NewDbgUiDebugActiveProcess()>>> ProcessHandle:" << hex << Process << endl;
	/* Tell the kernel to start debugging */
	Status = NtDebugActiveProcess(Process, NtCurrentTeb()->DbgSsReserved[1]);
	cout << "NtDebugActiveProcess() called NtCurrentTeb()->DbgSsReserved[1]:" << NtCurrentTeb()->DbgSsReserved[1] << "  status:" << Status << endl;
	if (NT_SUCCESS(Status))
	{
		/* Now break-in the process */
		Status = DbgUiIssueRemoteBreakin(Process);
		cout << "DbgUiIssueRemoteBreakin() called  status:" << Status << endl;
		if (!NT_SUCCESS(Status))
		{
			/* We couldn't break-in, cancel debugging */
			DbgUiStopDebugging(Process);
		}
	}

	return Status;
}

NTSTATUS NTAPI hook::NewDbgUiWaitStateChange(
	OUT PDBGUI_WAIT_STATE_CHANGE StateChange,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	//return NtWaitForDebugEvent(_DebugObjectHandle, TRUE, Timeout, StateChange);	// obh4
	return NtWaitForDebugEvent(NtCurrentTeb()->DbgSsReserved[1], TRUE, Timeout, StateChange);	
}

typedef NTSTATUS (*fpNtWaitForDebugEvent)(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN OPTIONAL PLARGE_INTEGER Timeout,
	OUT PVOID pStateChange);

NTSTATUS hook::NewNtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN OPTIONAL PLARGE_INTEGER Timeout,
	OUT PVOID pStateChange)
{
	return ((fpNtWaitForDebugEvent)_This->_Original_NtWaitForDebugEvent)(_DebugObjectHandle, TRUE, Timeout, pStateChange);	// obh4
}

NTSTATUS NTAPI hook::NewDbgUiContinue(
	IN PCLIENT_ID AppClientId,
	IN NTSTATUS ContinueStatus)
{
	//return NtDebugContinue(_DebugObjectHandle, AppClientId, ContinueStatus);	// obh5
	return NtDebugContinue(NtCurrentTeb()->DbgSsReserved[1], AppClientId, ContinueStatus);
}

typedef NTSTATUS (*fpNtDebugContinue)(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus);

NTSTATUS NTAPI hook::NewNtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus)
{
	return ((fpNtDebugContinue)_This->_Original_NtDebugContinue)(_DebugObjectHandle, ClientId, ContinueStatus);	// obh5
}

HANDLE NTAPI hook::NewDbgUiGetThreadDebugObject()
{
	return _DebugObjectHandle;	// obh6
	//return NtCurrentTeb()->DbgSsReserved[1];
}

NTSTATUS hook::NewDbgUiIssueRemoteBreakin(IN HANDLE processHandle)
{
	return STATUS_SUCCESS;
}