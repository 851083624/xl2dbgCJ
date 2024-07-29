#include "r0_newfunc.h"

#include "Get_SSDT.h"

r0_newfunc* r0_newfunc::_This = nullptr;
KernelHookEngine* hkEngin = nullptr;

r0_newfunc& r0_newfunc::getInstance()
{
    static r0_newfunc instance;
    return instance;
}
r0_newfunc::r0_newfunc()
{
    // 构造函数 仅第一次创建调用
	InitializeListHead(&debugLinkListHead);
	_This = this;
	hkEngin = KernelHookEngine::getInstance()._This;
}

VOID r0_newfunc::init(ULONG64 ntos_base_addr)
{
	DbgPrint("[xl2kerneldbg]call r0_newfunc::init...\n");
	_PsSystemDllBase = (PVOID)ntos_base_addr;

		//初始化SSDT函数
	NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSSDTFuncCurAddrByIndex(NtSysAPI_SSDT_NtProtectVirtualMemory);
	if (NtProtectVirtualMemory == nullptr)
	{
		DbgPrint("[xl2kerneldbg]call r0_newfunc::init....GetSSDTFuncCurAddrByIndex NtSysAPI_SSDT_NtProtectVirtualMemory fail!\n");
		return;
	}

	RTL_OSVERSIONINFOW Version = { 0 };
	Version.dwOSVersionInfoSize = sizeof(Version);

	NTSTATUS status = RtlGetVersion(&Version);
	DbgPrint("[xzzkernel]RtlGetVersion status: %x", status);
	if (NT_SUCCESS(status))
	{
		if (Version.dwBuildNumber == 7600)
		{
			//初始化符号函数 7600
			_DbgkDebugObjectType = (POBJECT_TYPE*)(ntos_base_addr + 0x200ED8);
			DbgkpWakeTarget = (_DbgkpWakeTarget)(ntos_base_addr + 0x41AB50);
			PsResumeThread = (_PsResumeThread)(ntos_base_addr + 0x3FF140);
			PsSuspendThread = (_PsSuspendThread)(ntos_base_addr + 0x2C43DC);
			PsGetNextProcessThread = (_PsGetNextProcessThread)(ntos_base_addr + 0x316EE0);
			DbgkpSectionToFileHandle = (_DbgkpSectionToFileHandle)(ntos_base_addr + 0x486170);
			MmGetFileNameForAddress = (_MmGetFileNameForAddress)(ntos_base_addr + 0x485D90);
			KiDispatchException = (_KiDispatchException)(ntos_base_addr + 0xAC080);
			DbgkForwardException = (_DbgkForwardException)(ntos_base_addr + 0x312C80);
			DbgkpSuspendProcess = (_DbgkpSuspendProcess)(ntos_base_addr + 0x3FEBE0);
			KeThawAllThreads = (_KeThawAllThreads)(ntos_base_addr + 0x12F790);
			DbgkCreateThread = (_DbgkCreateThread)(ntos_base_addr + 0x33BF40);
			DbgkMapViewOfSection = (_DbgkMapViewOfSection)(ntos_base_addr + 0x38DAFC);
			DbgkUnMapViewOfSection = (_DbgkUnMapViewOfSection)(ntos_base_addr + 0x342704);
			NtCreateUserProcess = (_NtCreateUserProcess)(ntos_base_addr + 0x31C080);
			DbgkpMarkProcessPeb = (_DbgkpMarkProcessPeb)(ntos_base_addr + 0x409810);
			DbgkpSuppressDbgMsg = (_DbgkpSuppressDbgMsg)(ntos_base_addr + 0x3F0BF0);

			_oriNtCreateDebugObject = (_NtCreateDebugObject)(ntos_base_addr + 0x452180);
			_oriNtDebugActiveProcess = (_NtDebugActiveProcess)(ntos_base_addr + 0x4C1A40);

			p_DbgkpProcessDebugPortMutex = (FAST_MUTEX*)(ntos_base_addr + 0x275920);

			_oriDbgkpQueueMessage = (_DbgkpQueueMessage)(ntos_base_addr + 0x414990);
			_oriDbgkpPostFakeProcessCreateMessages = (_DbgkpPostFakeProcessCreateMessages)(ntos_base_addr + 0x4C12E0);

			DbgPrint("init sym 7600 \n");
		}

		if (Version.dwBuildNumber == 7601)
		{
			//初始化符号函数
			_DbgkDebugObjectType = (POBJECT_TYPE*)(ntos_base_addr + 0x1fc0d0);
			DbgkpWakeTarget = (_DbgkpWakeTarget)(ntos_base_addr + 0x42E860);
			PsResumeThread = (_PsResumeThread)(ntos_base_addr + 0x3C5E00);
			PsSuspendThread = (_PsSuspendThread)(ntos_base_addr + 0x2BF5E8);
			PsGetNextProcessThread = (_PsGetNextProcessThread)(ntos_base_addr + 0x301CD8);
			DbgkpSectionToFileHandle = (_DbgkpSectionToFileHandle)(ntos_base_addr + 0x45AAB0);
			MmGetFileNameForAddress = (_MmGetFileNameForAddress)(ntos_base_addr + 0x45A6D0);
			KiDispatchException = (_KiDispatchException)(ntos_base_addr + 0x17A920);
			DbgkForwardException = (_DbgkForwardException)(ntos_base_addr + 0x4324C0);
			DbgkpSuspendProcess = (_DbgkpSuspendProcess)(ntos_base_addr + 0x3C58C0);
			KeThawAllThreads = (_KeThawAllThreads)(ntos_base_addr + 0x10CC90);
			DbgkCreateThread = (_DbgkCreateThread)(ntos_base_addr + 0x2D6760);
			DbgkMapViewOfSection = (_DbgkMapViewOfSection)(ntos_base_addr + 0x2D9BD0);
			DbgkUnMapViewOfSection = (_DbgkUnMapViewOfSection)(ntos_base_addr + 0x2D3F58);
			NtCreateUserProcess = (_NtCreateUserProcess)(ntos_base_addr + 0x4DCC40);
			DbgkpMarkProcessPeb = (_DbgkpMarkProcessPeb)(ntos_base_addr + 0x3D1370);
			DbgkpSuppressDbgMsg = (_DbgkpSuppressDbgMsg)(ntos_base_addr + 0x3B6DB0);

			_oriNtCreateDebugObject = (_NtCreateDebugObject)(ntos_base_addr + 0x419BB0);
			_oriNtDebugActiveProcess = (_NtDebugActiveProcess)(ntos_base_addr + 0x4A4930);

			p_DbgkpProcessDebugPortMutex = (FAST_MUTEX*)(ntos_base_addr + 0x271760);

			_oriDbgkpQueueMessage = (_DbgkpQueueMessage)(ntos_base_addr + 0x3DC610);
			_oriDbgkpPostFakeProcessCreateMessages = (_DbgkpPostFakeProcessCreateMessages)(ntos_base_addr + 0x4A41E0);

			DbgPrint("init sym 7601 \n");
		}
	}

	DbgPrint("KiDispatchException addr:%llx\n", KiDispatchException);
	DbgPrint("DbgkForwardException addr:%llx\n", DbgkForwardException);
	DbgPrint("DbgkCreateThread addr:%llx\n", DbgkCreateThread);
	DbgPrint("DbgkMapViewOfSection addr:%llx\n", DbgkMapViewOfSection);
	DbgPrint("DbgkUnMapViewOfSection addr:%llx\n", DbgkUnMapViewOfSection);
	DbgPrint("NtCreateUserProcess addr:%llx\n", NtCreateUserProcess);

	//__debugbreak();

	//ExInitializeFastMutex(&KiGenericCallDpcMutex);
	//ExInitializeFastMutex(&KiGenericCallDpcMutex2);


}

void r0_newfunc::startHook()
{
	if (hooked) return;

	NewDbgkForwardExceptionHookInfo = hkEngin->hook(DbgkForwardException, NewDbgkForwardException);
	NewDbgkCreateThreadHookInfo = hkEngin->hook(DbgkCreateThread, NewDbgkCreateThread);
	NewDbgkMapViewOfSectionHookInfo = hkEngin->hook(DbgkMapViewOfSection, NewDbgkMapViewOfSection);
	NewDbgkUnMapViewOfSectionHookInfo = hkEngin->hook(DbgkUnMapViewOfSection, NewDbgkUnMapViewOfSection);
	NewDbgkpQueueMessageHookInfo = hkEngin->hook(_oriDbgkpQueueMessage, PrivateDbgkpQueueMessage);
	// 
	//NewNtCreateUserProcessHookInfo = hkEngin->hook(NtCreateUserProcess, NewNtCreateUserProcess);
	//NewKiDispatchExceptionHookInfo = hkEngin->hook(KiDispatchException, NewKiDispatchException);
	hooked = true;
	DbgPrint("[xl2kerneldbg] hook open...\n");
}
void r0_newfunc::stopHook()
{
	if (!hooked) return;

	hkEngin->unhook(NewKiDispatchExceptionHookInfo);
	hkEngin->unhook(NewDbgkForwardExceptionHookInfo);
	hkEngin->unhook(NewDbgkCreateThreadHookInfo);
	hkEngin->unhook(NewDbgkMapViewOfSectionHookInfo);
	hkEngin->unhook(NewDbgkUnMapViewOfSectionHookInfo);
	hkEngin->unhook(NewDbgkpQueueMessageHookInfo);
	hkEngin->unhook(NewNtCreateUserProcessHookInfo);
	hooked = false;
	DbgPrint("[xl2kerneldbg] hook close...\n");
}

#define ProbeForWriteHandle(Address) {                                       \
    if ((Address) >= (HANDLE * const)MM_USER_PROBE_ADDRESS) {                \
        *(volatile HANDLE * const)MM_USER_PROBE_ADDRESS = 0;                 \
    }                                                                        \
                                                                             \
    *(volatile HANDLE *)(Address) = *(volatile HANDLE *)(Address);           \
}

NTSTATUS r0_newfunc::NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory* message)
{
	HANDLE ProcessHandle = message->ProcessHandle;
	PVOID BaseAddress = message->BaseAddress;
	void* Buffer = message->Buffer;
	SIZE_T BufferSize = message->BufferBytes;
	PSIZE_T NumberOfBytesWritten = message->ReturnBytes;

	SIZE_T BytesCopied;
	KPROCESSOR_MODE PreviousMode;
	PEPROCESS Process;
	NTSTATUS Status;
	PETHREAD CurrentThread;

	PAGED_CODE();

	CurrentThread = PsGetCurrentThread();
	PreviousMode = KeGetPreviousMode();
	if (PreviousMode != KernelMode)
	{

		if (((PCHAR)BaseAddress + BufferSize < (PCHAR)BaseAddress) ||
			((PCHAR)Buffer + BufferSize < (PCHAR)Buffer) ||
			((PVOID)((PCHAR)BaseAddress + BufferSize) > MM_HIGHEST_USER_ADDRESS) ||
			((PVOID)((PCHAR)Buffer + BufferSize) > MM_HIGHEST_USER_ADDRESS))
		{
			return STATUS_ACCESS_VIOLATION;
		}

		if (ARGUMENT_PRESENT(NumberOfBytesWritten))
		{
			__try
			{
				ProbeForWrite(NumberOfBytesWritten, sizeof(PSIZE_T), sizeof(ULONG));
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}
	}

	BytesCopied = 0;
	Status = STATUS_SUCCESS;
	if (BufferSize != 0)
	{
		do
		{
			PEPROCESS temp_process;
			Status = PsLookupProcessByProcessId((HANDLE)message->ProcessId, &temp_process);
			if (!NT_SUCCESS(Status))
			{
				break;
			}
			if (message->Read)
			{
				Status = MmCopyVirtualMemory(temp_process, (PVOID)message->BaseAddress, PsGetCurrentProcess(),
					message->Buffer, message->BufferBytes, PreviousMode, &BytesCopied);
			}
			else
			{
				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), message->Buffer, temp_process,
					(PVOID)message->BaseAddress, message->BufferBytes, PreviousMode, &BytesCopied);
			}
			ObDereferenceObject(temp_process);
		} while (false);
	}

	if (ARGUMENT_PRESENT(NumberOfBytesWritten))
	{
		__try
		{
			*NumberOfBytesWritten = BytesCopied;

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			NOTHING;
		}
	}

	return Status;
}

NTSTATUS r0_newfunc::NewNtOpenProcess(Message_NewNtOpenProcess* message)
{
	PHANDLE ProcessHandle = message->ProcessHandle;
	ACCESS_MASK DesiredAccess = message->DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes = message->ObjectAttributes;
	PCLIENT_ID ClientId = message->ClientId;

	HANDLE Handle;
	KPROCESSOR_MODE PreviousMode;
	NTSTATUS Status;
	PEPROCESS Process;
	PETHREAD Thread;
	CLIENT_ID CapturedCid = { 0 };
	BOOLEAN ObjectNamePresent;
	BOOLEAN ClientIdPresent;
	ACCESS_STATE AccessState;
	AUX_ACCESS_DATA AuxData;
	ULONG Attributes;

	DbgPrint("[xl2kerneldbg] called NewNtOpenProcess pProcessHandle:%llx, DesiredAccess:%x, ObjectAttributes:%llx, message->ClientId:%d,%x\n",
		ProcessHandle, DesiredAccess, ObjectAttributes, message->ClientId->UniqueProcess, message->ClientId->UniqueProcess);

	//__debugbreak();

	PEPROCESS temp_process;
	Status = PsLookupProcessByProcessId((HANDLE)message->ClientId->UniqueProcess, &temp_process);
	if (!NT_SUCCESS(Status))
	{
		return STATUS_UNSUCCESSFUL;
	}
	ObDereferenceObject(temp_process);


	PreviousMode = KeGetPreviousMode();
	if (PreviousMode != KernelMode)
	{
		__try
		{
			ProbeForWriteHandle(ProcessHandle);

			ProbeForRead(ObjectAttributes,
				sizeof(OBJECT_ATTRIBUTES),
				sizeof(ULONG));
			ObjectNamePresent = (BOOLEAN)ARGUMENT_PRESENT(ObjectAttributes->ObjectName);
			Attributes = ObjectAttributes->Attributes;

			if (ARGUMENT_PRESENT(ClientId))
			{
				//ProbeForReadSmallStructure(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
				CapturedCid = *ClientId;
				ClientIdPresent = TRUE;
			}
			else
			{
				ClientIdPresent = FALSE;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}
	else
	{
		ObjectNamePresent = (BOOLEAN)ARGUMENT_PRESENT(ObjectAttributes->ObjectName);
		Attributes = ObjectAttributes->Attributes;
		if (ARGUMENT_PRESENT(ClientId))
		{
			CapturedCid = *ClientId;
			ClientIdPresent = TRUE;
		}
		else
		{
			ClientIdPresent = FALSE;
		}
	}

	if (ObjectNamePresent && ClientIdPresent)
	{
		return STATUS_INVALID_PARAMETER_MIX;
	}

	Status = SeCreateAccessState(
		&AccessState,
		&AuxData,
		DesiredAccess,
		&(*PsProcessType)->TypeInfo.GenericMapping);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//http://www.rohitab.com/discuss/topic/39981-kernel-hack-hooking-sesingleprivilegecheck-to-bypass-privilege-checks/
	AccessState.PreviouslyGrantedAccess |= PROCESS_ALL_ACCESS;//直接给最高权限
	/*if (SeSinglePrivilegeCheck(SeDebugPrivilege, PreviousMode))
	{
		if (AccessState.RemainingDesiredAccess & MAXIMUM_ALLOWED)
		{
			AccessState.PreviouslyGrantedAccess |= PROCESS_ALL_ACCESS;
		}
		else
		{
			AccessState.PreviouslyGrantedAccess |= (AccessState.RemainingDesiredAccess);
		}
		AccessState.RemainingDesiredAccess = 0;
	}*/

	if (ObjectNamePresent)
	{
		Status = ObOpenObjectByName(
			ObjectAttributes,
			*PsProcessType,
			PreviousMode,
			&AccessState,
			0,
			NULL,
			&Handle);//打不开只能改句柄表 类BE循环去权限的无解 不改句柄表可能会不支持CE搜索
		SeDeleteAccessState(&AccessState);
		if (NT_SUCCESS(Status))
		{
			__try
			{
				*ProcessHandle = Handle;
				DbgPrint("[xl2kerneldbg] called NewNtOpenProcess success 11111 ===========> Handle:%llx, message->ClientId:%d,%x\n",
					Handle, message->ClientId->UniqueProcess, message->ClientId->UniqueProcess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		return Status;
	}

	if (ClientIdPresent)
	{
		Thread = NULL;
		if (CapturedCid.UniqueThread)
		{
			Status = PsLookupProcessThreadByCid(&CapturedCid, &Process, &Thread);
			if (!NT_SUCCESS(Status))
			{
				SeDeleteAccessState(&AccessState);
				return Status;
			}
		}
		else
		{
			Status = PsLookupProcessByProcessId(CapturedCid.UniqueProcess, &Process);
			if (!NT_SUCCESS(Status)) {
				SeDeleteAccessState(&AccessState);
				return Status;
			}
		}
		Status = ObOpenObjectByPointer(
			Process,
			Attributes,
			&AccessState,
			0,
			*PsProcessType,
			PreviousMode,
			&Handle
		);
		SeDeleteAccessState(&AccessState);
		if (Thread)
		{
			ObDereferenceObject(Thread);
		}
		ObDereferenceObject(Process);
		if (NT_SUCCESS(Status))
		{
			__try
			{
				*ProcessHandle = Handle;
				DbgPrint("[xl2kerneldbg] called NewNtOpenProcess success 22222 ===========> Handle:%llx, message->ClientId:%d,%x\n",
					Handle, message->ClientId->UniqueProcess, message->ClientId->UniqueProcess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}
		return Status;
	}
	return STATUS_INVALID_PARAMETER_MIX;
}


NTSTATUS r0_newfunc::NewNtCreateDebugObject(Message_NewNtCreateDebugObject* message)
{
	PHANDLE DebugObjectHandle = message->DebugObjectHandle;
	ACCESS_MASK DesiredAccess = message->DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes = message->ObjectAttributes;
	ULONG Flags = message->Flags;
	
	NTSTATUS Status=0;
	HANDLE Handle = nullptr;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject = nullptr;

	DbgPrint("[xl2kerneldbg] call start NewNtCreateDebugObject pDebugObjectHandle:%llx, DesiredAccess:%x, ObjectAttributes:%llx, Flags:%x\n",
		DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);


	Status = (_This->_oriNtCreateDebugObject)(DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);

	DbgPrint("[xl2kerneldbg] called _oriNtCreateDebugObject ===========> status:%x Handle:%llx \n",
		Status , *DebugObjectHandle);

	KPROCESSOR_MODE AccessMode = KeGetPreviousMode();
	Status = ObReferenceObjectByHandle(*DebugObjectHandle, DEBUG_PROCESS_ASSIGN, *_DbgkDebugObjectType, AccessMode, (PVOID*)&DebugObject, 0);
	if (Status == 0)
	{
		insertDebugObject(DebugObject, *DebugObjectHandle);
	}

	return Status;


	PreviousMode = KeGetPreviousMode();

	__try
	{
		if (PreviousMode != KernelMode)
		{
			ProbeForWriteHandle(DebugObjectHandle);
		}
		*DebugObjectHandle = NULL;//判断内存是否可写 实际上不返回 不需要内存也行
	}
	__except (1) //ExSystemExceptionFilter()
	{ // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}
	
	if (Flags & ~DEBUG_KILL_ON_CLOSE)
	{
		return STATUS_INVALID_PARAMETER;
	}

	Status = ObCreateObject(PreviousMode,
		*_DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	
	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);
	
	if (Flags & DEBUG_KILL_ON_CLOSE)
	{
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else
	{
		DebugObject->Flags = 0;
	}

	Status = ObInsertObject(DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//__try 
	//{
	//	*DebugObjectHandle = Handle;
	//} __except(ExSystemExceptionFilter()) 
	//{
	//	//创建时不返回句柄对象 句柄对象是无效的
	//	Status = GetExceptionCode();
	//}
	*message->DebugObjectHandle = Handle;//返回句柄

	
	// 	// todo ml
	//DebugInfomation* temp_debuginfo = new DebugInfomation();
	//temp_debuginfo->SourceProcessId = PsGetCurrentProcessId();
	//temp_debuginfo->DebugObject = DebugObject;
	//temp_debuginfo->DebugObjectHandle = Handle;

	//_DebugInfomationVector.push_back(temp_debuginfo);


	//DebugInfomation* temp_debuginfo;
	//PLIST_ENTRY pEntry = debugLinkListHead.Blink;
	//// 删除 已存在
	//do
	//{
	//	temp_debuginfo = CONTAINING_RECORD(pEntry, DebugInfomation, ListEntry);
	//	if (temp_debuginfo->SourceProcessId == PsGetCurrentProcessId())
	//	{
	//		DbgPrint("[xl2kerneldbg]remove DebugInfomation  temp_debuginfo->SourceProcessId:%d \n", temp_debuginfo->SourceProcessId);
	//		RemoveEntryList((PLIST_ENTRY)pEntry);
	//		ExFreePool(temp_debuginfo);
	//	}
	//	pEntry = pEntry->Blink;
	//} while (pEntry->Blink != &debugLinkListHead);

	////分配内核栈空间
	//temp_debuginfo = (DebugInfomation*)ExAllocatePool(PagedPool, sizeof(DebugInfomation));
	//RtlZeroMemory(temp_debuginfo, sizeof(DebugInfomation));
	//temp_debuginfo->SourceProcessId = PsGetCurrentProcessId();
	//temp_debuginfo->DebugObject = DebugObject;
	//temp_debuginfo->DebugObjectHandle = Handle;

	//// 插入元素到
	//InsertTailList(&debugLinkListHead, &temp_debuginfo->ListEntry);

	DebugInformation* temp_debuginfo = insertDebugObject(DebugObject, Handle);

	DbgPrint("[xl2kerneldbg] called NewNtCreateDebugObject success ===========> Handle:%llx, temp_debuginfo:%llx \n",
		Handle, temp_debuginfo);

	return Status;
}

DebugInformation* r0_newfunc::insertDebugObject(PDEBUG_OBJECT DebugObject, HANDLE Handle)
{
	DebugInformation* temp_debuginfo;
	PLIST_ENTRY pEntry = debugLinkListHead.Blink;
	// 删除 已存在
	do
	{
		temp_debuginfo = CONTAINING_RECORD(pEntry, DebugInformation, ListEntry);
		if (temp_debuginfo->SourceProcessId == PsGetCurrentProcessId())
		{
			DbgPrint("[xl2kerneldbg]remove DebugInfomation  temp_debuginfo->SourceProcessId:%d \n", temp_debuginfo->SourceProcessId);
			RemoveEntryList((PLIST_ENTRY)pEntry);
			ExFreePool(temp_debuginfo);
		}
		pEntry = pEntry->Blink;
	} while (pEntry->Blink != &debugLinkListHead);

	//分配内核栈空间
	temp_debuginfo = (DebugInformation*)ExAllocatePool(PagedPool, sizeof(DebugInformation));
	RtlZeroMemory(temp_debuginfo, sizeof(DebugInformation));
	temp_debuginfo->SourceProcessId = PsGetCurrentProcessId();	// 保存时源进程id为当前进程pid(调试进程)
	temp_debuginfo->DebugObject = DebugObject;
	temp_debuginfo->DebugObjectHandle = Handle;

	// 插入元素到
	InsertTailList(&debugLinkListHead, &temp_debuginfo->ListEntry);

	DbgPrint("[xl2kerneldbg] insertDebugObject success ===========> Handle:%llx, temp_debuginfo:%llx \n",
		Handle, temp_debuginfo);

	return temp_debuginfo;
}

DebugInformation* r0_newfunc::findDebugInfoByProcessId(HANDLE SourceProcessId, HANDLE TargetProcessId)
{

	if (IsListEmpty(&debugLinkListHead))
	{
		return NULL;
	}
	
	PLIST_ENTRY pEntry = debugLinkListHead.Blink;

	DebugInformation* debugInfo;
	if ((ULONG)SourceProcessId == -2 && (ULONG)TargetProcessId == -2)
	{
		return NULL;
	}

	do
	{
		debugInfo = CONTAINING_RECORD(pEntry, DebugInformation, ListEntry);
		if ((ULONG)SourceProcessId != -2 && debugInfo->SourceProcessId == SourceProcessId)
		{
			return debugInfo;
		}
		if ((ULONG)TargetProcessId != -2 && debugInfo->TargetProcessId == TargetProcessId)
		{
			return debugInfo;
		}
		pEntry = pEntry->Blink;
	} while (pEntry->Blink != &debugLinkListHead);

	//DbgPrint("[testxl2dbg] findDebugInfoByProcessId fail SourceProcessId:%d, TargetProcessId:%d\n", SourceProcessId, TargetProcessId);
	return nullptr;
}

NTSTATUS r0_newfunc::NewNtDebugActiveProcess(Message_NewNtDebugActiveProcess* message)
{
	HANDLE ProcessHandle = message->ProcessHandle;
	HANDLE DebugObjectHandle = message->DebugObjectHandle;

	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject = nullptr;
	PEPROCESS Process;
	PETHREAD LastThread = nullptr;

	//Status = (_This->_oriNtDebugActiveProcess)(ProcessHandle, DebugObjectHandle);

	//DbgPrint("[xl2kerneldbg] called _oriNtDebugActiveProcess ===========> status:%x, ProcessHandle:%llx, DebugObjectHandle:%llx \n",
	//	Status ,ProcessHandle, DebugObjectHandle);

	//return Status;


	DbgPrint("[xl2kerneldbg] start call NewNtDebugActiveProcess ===========> ProcessHandle:%llx, DebugObjectHandle:%llx \n",
		ProcessHandle, DebugObjectHandle);

	PreviousMode = KeGetPreviousMode();

	Status = PsLookupProcessByProcessId((HANDLE)message->ProcessId, &Process);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	if (Process == PsGetCurrentProcess() || Process == PsInitialSystemProcess)
	{
		ObDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}


	HANDLE cur_pid = PsGetCurrentProcessId();
	DebugInformation* debugInfo = findDebugInfoByProcessId(cur_pid, (HANDLE)-2);
	if (debugInfo == nullptr)
	{
		return STATUS_ABANDONED;
	}

	debugInfo->TargetProcessId = message->ProcessId;
	DebugObject = debugInfo->DebugObject;

	if (NT_SUCCESS(Status))
	{
		if (ExAcquireRundownProtection(PrivateGetProcessRundownProtect(Process)))
		{
			//DbgPrint("NewNtDebugActiveProcess: disable PrivateDbgkpPostFakeProcessCreateMessages and PrivateDbgkpSetProcessDebugObject ...");
			Status = PrivateDbgkpPostFakeProcessCreateMessages(Process, DebugObject, &LastThread);
			Status = PrivateDbgkpSetProcessDebugObject(Process, DebugObject, Status, LastThread);

			ExReleaseRundownProtection(PrivateGetProcessRundownProtect(Process));
		}
		else
		{
			Status = STATUS_PROCESS_IS_TERMINATING;
		}
		//ObDereferenceObject(DebugObject);//不需要解引用
	}
	ObDereferenceObject(Process);


	DbgPrint("[xl2kerneldbg] called NewNtDebugActiveProcess ===========> Status:%x \n", Status);

	return Status;
}

NTSTATUS r0_newfunc::NewNtRemoveProcessDebug(Message_NewNtRemoveProcessDebug* message)
{
	return STATUS_SUCCESS;
}



#pragma region 私有函数

NTSTATUS NTAPI r0_newfunc::PrivateDbgkpPostFakeProcessCreateMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread)
{

	return _This->_oriDbgkpPostFakeProcessCreateMessages(Process, DebugObject, pLastThread);

	////////////////////////////////////////////////////////////////////////////

	NTSTATUS Status = STATUS_SUCCESS;
	PETHREAD LastThread = NULL;
	KAPC_STATE ApcState;
	PETHREAD Thread;

	PAGED_CODE();

	KeStackAttachProcess((PKPROCESS)Process, &ApcState);

	Status = PrivateDbgkpPostFakeThreadMessages(Process, DebugObject, NULL, &Thread, &LastThread);

	if (NT_SUCCESS(Status)) {
		Status = PrivateDbgkpPostFakeModuleMessages(Process, Thread, DebugObject);
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(LastThread);
			LastThread = NULL;
		}
		ObDereferenceObject(Thread);
	} else {
		LastThread = NULL;
	}
	
	KeUnstackDetachProcess(&ApcState);

	*pLastThread = LastThread;

	return Status;
}

NTSTATUS NTAPI r0_newfunc::PrivateDbgkpPostFakeThreadMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD StartThread,
	OUT PETHREAD* pFirstThread,
	OUT PETHREAD* pLastThread)
/*++

Routine Description:

	This routine posts the faked initial process create, thread create messages

Arguments:

	Process      - Process to be debugged
	DebugObject  - Debug object to queue messages to
	StartThread  - Thread to start search from
	pFirstThread - First thread found in the list
	pLastThread  - Last thread found in the list

Return Value:

	None.

--*/
{

	NTSTATUS Status;
	PETHREAD Thread, FirstThread, LastThread;
	DBGKM_APIMSG ApiMsg;
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	NTSTATUS Status1;

	PAGED_CODE();

	LastThread = FirstThread = NULL;

	Status = STATUS_UNSUCCESSFUL;

	//bool exOnece = false;

	if (StartThread != NULL) {
		First = FALSE;
		FirstThread = StartThread;
		ObReferenceObject(FirstThread);
	}
	else {
		StartThread = PsGetNextProcessThread(Process, NULL);
		First = TRUE;
	}

	for (Thread = StartThread;
		Thread != NULL;
		Thread = PsGetNextProcessThread(Process, Thread)) {

		//if (exOnece) break;
		//exOnece = true;

		Flags = DEBUG_EVENT_NOWAIT;

		//
		// Keep a track ont he last thread we have seen.
		// We use this as a starting point for new threads after we
		// really attach so we can pick up any new threads.
		//
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
		LastThread = Thread;
		ObReferenceObject(LastThread);

		//
		// Acquire rundown protection of the thread.
		// This stops the thread exiting so we know it can't send
		// it's termination message
		//
		if (ExAcquireRundownProtection(PrivateGetThreadRundownProtect(Thread))) {	// &Thread->RundownProtect
			Flags |= DEBUG_EVENT_RELEASE;

			//
			// Suspend the thread if we can for the debugger
			// We don't suspend terminating threads as we will not be giving details
			// of these to the debugger.
			//

			if (!IS_SYSTEM_THREAD(Thread)) {
				//DbgPrint("Thread skip Suspend Thread:%llx\n", Thread);
				Status1 = PsSuspendThread(Thread, NULL);
				if (NT_SUCCESS(Status1)) {
					Flags |= DEBUG_EVENT_SUSPEND;
				}
			}
		}
		else {
			//
			// Rundown protection failed for this thread.
			// This means the thread is exiting. We will mark this thread
			// later so it doesn't sent a thread termination message.
			// We can't do this now because this attach might fail.
			//
			Flags |= DEBUG_EVENT_PROTECT_FAILED;
		}

		RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

		if (First && (Flags & DEBUG_EVENT_PROTECT_FAILED) == 0 &&
			!IS_SYSTEM_THREAD(Thread)) {	// && Thread->GrantedAccess
			IsFirstThread = TRUE;
		}
		else {
			IsFirstThread = FALSE;
		}

		if (IsFirstThread) {
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			if (PrivateGetProcessSectionObject(Process) != NULL) { // system process doesn't have one of these!	// Process->SectionObject
				ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpSectionToFileHandle(PrivateGetProcessSectionObject(Process));	// Process->SectionObject
			}
			else {
				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
			}
			ApiMsg.u.CreateProcessInfo.BaseOfImage = PsGetProcessSectionBaseAddress(Process); // Process->SectionBaseAddress;
			__try {
				NtHeaders = RtlImageNtHeader(PsGetProcessSectionBaseAddress(Process));	// Process->SectionBaseAddress
				if (NtHeaders) {
					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL; // Filling this in breaks MSDEV!
	//                        (PVOID)(NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
			}
		}
		else {
			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
			ApiMsg.u.CreateThread.StartAddress = PrivateGetThreadStartAddress(Thread);//Thread->StartAddress;
		}

		//Flags &= ~DEBUG_EVENT_RELEASE;
		//__debugbreak();

		Status = PrivateDbgkpQueueMessage(Process,
			Thread,
			&ApiMsg,
			Flags,
			DebugObject);
		
		// DbgkpSetProcessDebugObject所做事情
		//ObReferenceObject(DebugObject);
		//LIST_ENTRY* Entry = DebugObject->EventList.Flink;
		//DEBUG_EVENT* DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		//DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
		//KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
		////DebugEvent->BackoutThread = NULL;
		//PS_SET_BITS(PrivateGetThreadCrossThreadFlagsPoint(Thread),		// &Thread->CrossThreadFlags,
		//	PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);
		//if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
		//	DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
		//	ExReleaseRundownProtection(PrivateGetThreadRundownProtect(Thread));	// &Thread->RundownProtect
		//}

		//if (Flags & DEBUG_EVENT_SUSPEND) {
		//	PsResumeThread(Thread, NULL);
		//}
		//if (Flags & DEBUG_EVENT_RELEASE) {
		//	ExReleaseRundownProtection(PrivateGetThreadRundownProtect(Thread));	// &Thread->RundownProtect
		//}
		//if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
		//	ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
		//}

		//Status = STATUS_SUCCESS;
		//ObDereferenceObject(Process);
		//ObDereferenceObject(Thread);
		if (!NT_SUCCESS(Status)) {
			if (Flags & DEBUG_EVENT_SUSPEND) {
				PsResumeThread(Thread, NULL);
			}
			if (Flags & DEBUG_EVENT_RELEASE) {
				ExReleaseRundownProtection(PrivateGetThreadRundownProtect(Thread));	// &Thread->RundownProtect
			}
			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
				ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
			}
			//PsQuitNextProcessThread(Thread);
			ObDereferenceObject(Thread);
			break;
		} 
		else if (IsFirstThread) {
			First = FALSE;
			ObReferenceObject(Thread);
			FirstThread = Thread;
		}
	}

	if (!NT_SUCCESS(Status)) {
		if (FirstThread) {
			ObDereferenceObject(FirstThread);
		}
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
	}
	else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else {
			Status = STATUS_UNSUCCESSFUL;
		}
	}

	return Status;
}


NTSTATUS NTAPI r0_newfunc::PrivateDbgkpSetProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread)
/*++

Routine Description:

	Attach a debug object to a process.

Arguments:

	Process     - Process to be debugged
	DebugObject - Debug object to attach
	MsgStatus   - Status from queing the messages
	LastThread  - Last thread seen in attach loop.

Return Value:

	NTSTATUS - Status of call.

--*/
{
	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;

	PAGED_CODE();

	ThisThread = PsGetCurrentThread();

	InitializeListHead(&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS(MsgStatus)) {
		LastThread = NULL;
		Status = MsgStatus;
	}
	else {
		Status = STATUS_SUCCESS;
	}

	//
	// Pick up any threads we missed
	//
	if (NT_SUCCESS(Status)) {

		while (1) {
			//
			// Acquire the debug port mutex so we know that any new threads will
			// have to wait to behind us.
			//
			GlobalHeld = TRUE;

			ExAcquireFastMutex(p_DbgkpProcessDebugPortMutex);

			//
			// If the port has been set then exit now.
			//
			//if (Process->DebugPort != NULL) {
			//	Status = STATUS_PORT_ALREADY_SET;
			//	break;
			//}
			//
			// Assign the debug port to the process to pick up any new threads
			//
			//Process->DebugPort = DebugObject;
			//* (ULONG64*)((ULONG64)Process + 0x1f0) = (ULONG64)DebugObject;

			//
			// Reference the last thread so we can deref outside the lock
			//
			ObReferenceObject(LastThread);

			//
			// Search forward for new threads
			//
			Thread = PsGetNextProcessThread(Process, LastThread);
			if (Thread != NULL) {

				//
				// Remove the debug port from the process as we are
				// about to drop the lock
				//
				//Process->DebugPort = NULL;
				//*(ULONG64*)((ULONG64)Process + 0x1f0) = (ULONG64)0;

				ExReleaseFastMutex(p_DbgkpProcessDebugPortMutex);

				GlobalHeld = FALSE;

				ObDereferenceObject(LastThread);

				//
				// Queue any new thread messages and repeat.
				//

				Status = PrivateDbgkpPostFakeThreadMessages(Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status)) {
					LastThread = NULL;
					break;
				}
				ObDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}

	//
	// Lock the debug object so we can check its deleted status
	//
	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// We must not propagate a debug port thats got no handles left.
	//

	if (NT_SUCCESS(Status)) {
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			//PS_SET_BITS(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObReferenceObject(DebugObject);
		}
		else {
			//Process->DebugPort = NULL;
			//*(ULONG64*)((ULONG64)Process + 0x1f0) = (ULONG64)0;
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {

		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
			Thread = DebugEvent->Thread;

			//
			// If the thread has not been inserted by CreateThread yet then don't
			// create a handle. We skip system threads here also
			//
			if (NT_SUCCESS(Status) && !IS_SYSTEM_THREAD(Thread)) {	// && Thread->GrantedAccess != 0 
				//
				// If we could not acquire rundown protection on this
				// thread then we need to suppress its exit message.
				//
				if ((DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0) {
					PS_SET_BITS(PrivateGetThreadCrossThreadFlagsPoint(Thread),		// &Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					DebugEvent->BackoutThread = NULL;
					PS_SET_BITS(PrivateGetThreadCrossThreadFlagsPoint(Thread),		// &Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

				}
			}
			else {
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExReleaseRundownProtection(PrivateGetThreadRundownProtect(Thread));	// &Thread->RundownProtect
			}

		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld) {
		ExReleaseFastMutex(p_DbgkpProcessDebugPortMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget(DebugEvent);
	}

	//if (NT_SUCCESS(Status)) {
	//	DbgkpMarkProcessPeb(Process);
	//}

	return Status;
}

NTSTATUS r0_newfunc::PrivateDbgkpQueueMessage(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject)
	/*++

Routine Description:

	Queues a debug message to the port for a user mode debugger to get.

Arguments:

	Process           - Process being debugged
	Thread            - Thread making call
	ApiMsg            - Message being sent and received
	NoWait            - Don't wait for a response. Buffer message and return.
	TargetDebugObject - Port to queue nowait messages to

Return Value:

	NTSTATUS - Status of call.

--*/
{

	HANDLE cur_pid = PsGetCurrentProcessId();
	DebugInformation* debugInfo = _This->findDebugInfoByProcessId(cur_pid, cur_pid);
	if (debugInfo == nullptr)
	{
		
		return _This->_oriDbgkpQueueMessage(Process, Thread, ApiMsg, Flags, TargetDebugObject);
	}



	/////////////////////////////////////////////////////////////////////////////////////////

	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;

	PAGED_CODE();

	if (Flags & DEBUG_EVENT_NOWAIT) {
		DebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag((POOL_TYPE)(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE),
			sizeof(*DebugEvent),
			'EgbD');
		if (DebugEvent == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
		ObReferenceObject(Process);
		ObReferenceObject(Thread);
		DebugEvent->BackoutThread = PsGetCurrentThread();
		DebugObject = TargetDebugObject;
	}
	else {
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;

		ExAcquireFastMutex(_This->p_DbgkpProcessDebugPortMutex);
		//DebugObject = Process->DebugPort;

		HANDLE cur_pid = PsGetCurrentProcessId();
		DebugInformation* debugInfo = _This->findDebugInfoByProcessId(cur_pid, cur_pid);
		if (debugInfo == nullptr) return STATUS_ABANDONED;
		DebugObject = debugInfo->DebugObject;

		//
		// See if this create message has already been sent.
		//
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (_This->PrivateGetThreadCrossThreadFlags(Thread) & PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG) {	// Thread->CrossThreadFlags
				DebugObject = NULL;
			}
		}

		//
		// See if this exit message is for a thread that never had a create
		//
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (_This->PrivateGetThreadCrossThreadFlags(Thread) & PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG) {	// Thread->CrossThreadFlags
				DebugObject = NULL;
			}
		}
	}

	KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);

	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = { PsGetThreadProcessId(Thread) ,PsGetThreadId(Thread) };//Thread->Cid;

	if (DebugObject == NULL) {
		Status = STATUS_PORT_NOT_SET;
	}
	else {

		//
		// We must not use a debug port thats got no handles left.
		//
		ExAcquireFastMutex(&DebugObject->Mutex);

		//
		// If the object is delete pending then don't use this object.
		//
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
			//
			// Set the event to say there is an unread event in the object
			//
			if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);
	}


	if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
		ExReleaseFastMutex(_This->p_DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;

}

NTSTATUS NTAPI r0_newfunc::PrivateDbgkpPostFakeModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PDEBUG_OBJECT DebugObject)
/*++

Routine Description:

	This routine posts the faked module load messages when we debug an active process.

Arguments:

	ProcessHandle     - Handle to a process to be debugged
	DebugObjectHandle - Handle to a debug object

Return Value:

	None.

--*/
{
	PPEB Peb = PsGetProcessPeb(Process);
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY LdrHead, LdrNext;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	DBGKM_APIMSG ApiMsg;
	ULONG i;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING Name;
	PIMAGE_NT_HEADERS NtHeaders;
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;

	PAGED_CODE();

	if (Peb == NULL) {
		return STATUS_SUCCESS;
	}

	__try {
		Ldr = Peb->Ldr;

		LdrHead = &Ldr->InLoadOrderModuleList;

		ProbeForReadSmallStructure(LdrHead, sizeof(LIST_ENTRY), sizeof(UCHAR));
		for (LdrNext = LdrHead->Flink, i = 0;
			LdrNext != LdrHead && i < 500;
			LdrNext = LdrNext->Flink, i++) {

			//
			// First image got send with process create message
			//
			if (i > 0) {
				RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

				LdrEntry = CONTAINING_RECORD(LdrNext, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				ProbeForReadSmallStructure(LdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(UCHAR));

				ApiMsg.ApiNumber = DbgKmLoadDllApi;
				ApiMsg.u.LoadDll.BaseOfDll = LdrEntry->DllBase;
				ApiMsg.u.LoadDll.NamePointer = NULL;

				ProbeForReadSmallStructure(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

				NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
				if (NtHeaders) {
					ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
				Status = MmGetFileNameForAddress(NtHeaders, &Name);
				if (NT_SUCCESS(Status)) {
					InitializeObjectAttributes(&oa,
						&Name,
						OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						NULL,
						NULL);

					Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
						GENERIC_READ | SYNCHRONIZE,
						&oa,
						&iosb,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						FILE_SYNCHRONOUS_IO_NONALERT);
					if (!NT_SUCCESS(Status)) {
						ApiMsg.u.LoadDll.FileHandle = NULL;
					}
					ExFreePool(Name.Buffer);
				}
				Status = PrivateDbgkpQueueMessage(Process,
					Thread,
					&ApiMsg,
					DEBUG_EVENT_NOWAIT,
					DebugObject);
				if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {	// 
					ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
				}

			}
			ProbeForReadSmallStructure(LdrNext, sizeof(LIST_ENTRY), sizeof(UCHAR));
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	}

#if defined(_WIN64)
	if (PrivateGetProcessWow64Process(Process) != NULL && PrivateGetProcessWow64Process(Process)->Wow64 != NULL) {	// Process->Wow64Process
		PPEB32 Peb32;
		PPEB_LDR_DATA32 Ldr32;
		PLIST_ENTRY32 LdrHead32, LdrNext32;
		PLDR_DATA_TABLE_ENTRY32 LdrEntry32;
		PWCHAR pSys;

		Peb32 = (PPEB32)PrivateGetProcessWow64Process(Process)->Wow64;	// Process->Wow64Process

		__try {
			Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);

			LdrHead32 = &Ldr32->InLoadOrderModuleList;

			ProbeForReadSmallStructure(LdrHead32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink), i = 0;
				LdrNext32 != LdrHead32 && i < 500;
				LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink), i++) {

				if (i > 0) {
					RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

					LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					ProbeForReadSmallStructure(LdrEntry32, sizeof(LDR_DATA_TABLE_ENTRY32), sizeof(UCHAR));

					ApiMsg.ApiNumber = DbgKmLoadDllApi;
					ApiMsg.u.LoadDll.BaseOfDll = (PVOID)UlongToPtr(LdrEntry32->DllBase);
					ApiMsg.u.LoadDll.NamePointer = NULL;

					ProbeForReadSmallStructure(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

					NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
					if (NtHeaders) {
						ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
						ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
					}

					Status = MmGetFileNameForAddress(NtHeaders, &Name);
					if (NT_SUCCESS(Status)) {
						//ASSERT(sizeof(L"SYSTEM32") == sizeof(WOW64_SYSTEM_DIRECTORY_U));
						pSys = wcsstr(Name.Buffer, L"\\SYSTEM32\\");
						if (pSys != NULL) {
							RtlCopyMemory(pSys + 1,
								L"SysWOW64",// WOW64_SYSTEM_DIRECTORY_U,
								sizeof("SysWOW64") - sizeof(UNICODE_NULL));
						}

						InitializeObjectAttributes(&oa,
							&Name,
							OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
							NULL,
							NULL);

						Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
							GENERIC_READ | SYNCHRONIZE,
							&oa,
							&iosb,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
							FILE_SYNCHRONOUS_IO_NONALERT);
						if (!NT_SUCCESS(Status)) {
							ApiMsg.u.LoadDll.FileHandle = NULL;
						}
						ExFreePool(Name.Buffer);
					}

					Status = PrivateDbgkpQueueMessage(Process,
						Thread,
						&ApiMsg,
						DEBUG_EVENT_NOWAIT,
						DebugObject);
					if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL) { // 
						ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
					}
				}

				ProbeForReadSmallStructure(LdrNext32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

#endif
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI r0_newfunc::PrivateDbgkpSendApiMessage(
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN BOOLEAN SuspendProcess)
{
	//DbgPrint("[xl2kerneldbg] call start PrivateDbgkpSendApiMessage...\n");
	//DbgPrint("ApiMsg:%llx\n", ApiMsg);
	//DbgPrint("ApiMsg->ApiNumber:%x\n", ApiMsg->ApiNumber);
	//DbgPrint("ApiMsg->ReturnedStatus:%x\n", ApiMsg->ReturnedStatus);
	//DbgPrint("SuspendProcess:%x\n", SuspendProcess);
	//DbgPrint("ApiMsg->u.CreateThread.StartAddress:%llx\n", ApiMsg->u.CreateThread.StartAddress);
	//DbgPrint("---------------\n");

	NTSTATUS st;
	PEPROCESS Process;
	PAGED_CODE();
	if (SuspendProcess)
	{
		SuspendProcess = DbgkpSuspendProcess();
	}
	ApiMsg->ReturnedStatus = STATUS_PENDING;
	Process = PsGetCurrentProcess();
	PS_SET_BITS(PrivateGetProcessFlags(Process), PS_PROCESS_FLAGS_CREATE_REPORTED);
	st = PrivateDbgkpQueueMessage(Process, PsGetCurrentThread(), ApiMsg, 0, NULL);
	//if (ApiMsg->ApiNumber == DbgKmCreateProcessApi && ApiMsg->u.CreateProcessInfo.FileHandle != NULL) {
	//	ObCloseHandle(ApiMsg->u.CreateProcessInfo.FileHandle, KernelMode);
	//}
	//if (ApiMsg->u.LoadDll.FileHandle != NULL) {
	//	ObCloseHandle(ApiMsg->u.LoadDll.FileHandle, KernelMode);
	//}
	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);
	if (SuspendProcess)
	{
		KeThawAllThreads();
	}

	//DbgPrint("[xl2kerneldbg] PrivateDbgkpSendApiMessage called...status:%x\n", st);
	return st;
}

#pragma endregion


#pragma region HOOK函数

#ifdef _AMD64_
VOID NTAPI r0_newfunc::NewKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance)
#else
VOID NTAPI NewFunc::NewKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN void* ExceptionFrame,
	IN void* TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance)
#endif // _AMD64_
{

	return ((_KiDispatchException)_This->NewKiDispatchExceptionHookInfo->ori_api_address)(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);

	if (PreviousMode == KernelMode)
	{
	}
	else
	{
		//用户模式也有一次进入KiDebugRoutine的机会.
		//Kernel

		//User
		//if (FirstChance == true)
		{
			HANDLE temp_pid = PsGetCurrentProcessId();
			DebugInformation* debugInfo = _This->findDebugInfoByProcessId(temp_pid, temp_pid);

			if (debugInfo != NULL && debugInfo->TargetProcessId == temp_pid)
			{

				/*if ((_This->PrivateGetProcessWow64Process(PsGetCurrentProcess()) != NULL) &&
					(ExceptionRecord->ExceptionCode == STATUS_DATATYPE_MISALIGNMENT) &&
					((TrapFrame->EFlags & EFLAGS_AC_MASK) != 0))
				{
					TrapFrame->EFlags &= ~EFLAGS_AC_MASK;
					break;
				}*/

				if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
				{
					switch (ExceptionRecord->ExceptionCode)
					{
					case STATUS_BREAKPOINT:
						ExceptionRecord->ExceptionCode = STATUS_WX86_BREAKPOINT;
						break;
					case STATUS_SINGLE_STEP:
						ExceptionRecord->ExceptionCode = STATUS_WX86_SINGLE_STEP;
						break;
					}
				}

				//忽略ExceptionForwarded判断(debugobj
				//debugobject为空时,该函数不会被直接 所以捕获目标进程后直接转发过去
				if (NewDbgkForwardException(ExceptionRecord, TRUE, FALSE))
				{
					//DbgPrint("NewDbgkForwardException success ExceptionRecord->ExceptionCode:%llx\n", ExceptionRecord->ExceptionCode);
					//if ((ULONG)ExceptionRecord->ExceptionCode == 0x80000004)
					//	return;
					//如果调试器处理成功 直接返回 不继续处理了 仅只给一次机会.
					//return; //不返回模式专治各种主动制造异常
				}

				if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
				{
					switch (ExceptionRecord->ExceptionCode)
					{
					case STATUS_WX86_BREAKPOINT:
						ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
						break;
					case STATUS_WX86_SINGLE_STEP:
						ExceptionRecord->ExceptionCode = STATUS_SINGLE_STEP;
						break;
					}
				}
			}
		}
	}



	_KiDispatchException func = (_KiDispatchException)_This->NewKiDispatchExceptionHookInfo->ori_api_address;
	if (!func)
	{
		DbgBreakPoint();//必死无疑
	}
	//失败或正常进入 则再次执行
	return func(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
}

BOOLEAN NTAPI r0_newfunc::NewDbgkForwardException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance)
{
	PDBGKM_EXCEPTION args;
	DBGKM_APIMSG m;
	NTSTATUS st;


	HANDLE temp_pid = PsGetCurrentProcessId();
	DebugInformation* debugInfo = _This->findDebugInfoByProcessId(temp_pid, temp_pid);

	if (debugInfo != NULL && debugInfo->TargetProcessId == temp_pid)
	{
		//DbgPrint("[xl2kerneldbg] call start NewDbgkForwardException...\n");
		//DbgPrint("ExceptionRecord:%llx\n", ExceptionRecord);
		//DbgPrint("DebugException:%d\n", DebugException);
		//DbgPrint("SecondChance:%d\n", SecondChance);

		//捕获并确定为目标进程
		//忽略PS_CROSS_THREAD_FLAGS_HIDEFROMDBG
		//忽略Process->DebugPort
		//忽略LpcPort = FALSE;
		//if (DebugException == FALSE)
		//{
		//	DbgPrint("NewDbgkForwardException error DebugException == FALSE\n");
		//	return FALSE;
		//	DbgBreakPoint();//出现问题 该参数不应该为false
		//}
		//发送消息

		args = &m.u.Exception;

		DBGKM_FORMAT_API_MSG(m, DbgKmExceptionApi, sizeof(*args));

		args->ExceptionRecord = *ExceptionRecord;
		args->FirstChance = !SecondChance;

		st = _This->PrivateDbgkpSendApiMessage(&m, DebugException);

		if (!NT_SUCCESS(st) || ((DebugException) &&
			(m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED || !NT_SUCCESS(m.ReturnedStatus))))
		{
			return FALSE;//处理失败
		}
		return TRUE;//未出现问题 直接返回 不继续往下调用
	}

	_DbgkForwardException func = (_DbgkForwardException)_This->NewDbgkForwardExceptionHookInfo->ori_api_address;
	if (!func)
	{
		DbgBreakPoint();//等死吧...
	}
	//非目标进程 正常执行函数
	return func(ExceptionRecord, DebugException, SecondChance);
}

VOID NTAPI r0_newfunc::NewDbgkCreateThread(PETHREAD Thread, PVOID StartAddress)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_CREATE_THREAD CreateThreadArgs;
	PDBGKM_CREATE_PROCESS CreateProcessArgs;
	PEPROCESS Process = PsGetCurrentProcess();
	HANDLE ProcessId = PsGetCurrentProcessId();
	PDBGKM_LOAD_DLL LoadDllArgs;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	PIMAGE_NT_HEADERS NtHeaders;
	PTEB Teb;

	PAGED_CODE();

	HANDLE temp_pid = PsGetCurrentProcessId();
	DebugInformation* debugInfo = _This->findDebugInfoByProcessId(temp_pid, temp_pid);

	if (debugInfo != NULL && debugInfo->TargetProcessId == temp_pid)
	{
		//跳过PsCallImageNotifyRoutines 此过程和调试无关
		//忽略DebugPort
		//if (_This->PrivateGetProcessUserTime(Process))
		{
			//PS_SET_BITS(_This->PrivateGetProcessFlags(Process), PS_PROCESS_FLAGS_CREATE_REPORTED | PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);
		}

		auto temp_result = PS_TEST_SET_BITS(_This->PrivateGetProcessFlags(Process), 0x400001);

		if ((temp_result & PS_PROCESS_FLAGS_CREATE_REPORTED) == 0)
			//if (*_This->PrivateGetProcessFlags(Process) & PS_PROCESS_FLAGS_CREATE_REPORTED)
		{
			CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
			CreateThreadArgs->SubSystemKey = 0;

			CreateProcessArgs = &m.u.CreateProcessInfo;
			CreateProcessArgs->SubSystemKey = 0;
			CreateProcessArgs->FileHandle = _This->DbgkpSectionToFileHandle(_This->PrivateGetProcessSectionObject(Process));
			CreateProcessArgs->BaseOfImage = _This->PrivateGetProcessSectionBaseAddress(Process);
			CreateThreadArgs->StartAddress = NULL;
			CreateProcessArgs->DebugInfoFileOffset = 0;
			CreateProcessArgs->DebugInfoSize = 0;

			__try
			{
				NtHeaders = RtlImageNtHeader(_This->PrivateGetProcessSectionBaseAddress(Process));
				if (NtHeaders)
				{
					if (_This->PrivateGetProcessWow64Process(PsGetCurrentProcess()) != NULL)
					{
						CreateThreadArgs->StartAddress = UlongToPtr(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, ImageBase) +
							DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, AddressOfEntryPoint));
					}
					else {
						CreateThreadArgs->StartAddress = (PVOID)(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, ImageBase) +
							DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, AddressOfEntryPoint));
					}
					/*CreateThreadArgs->StartAddress = (PVOID)(
						NtHeaders->OptionalHeader.ImageBase +
						NtHeaders->OptionalHeader.AddressOfEntryPoint);*/
					CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				CreateThreadArgs->StartAddress = NULL;
				CreateProcessArgs->DebugInfoFileOffset = 0;
				CreateProcessArgs->DebugInfoSize = 0;
			}

			DBGKM_FORMAT_API_MSG(m, DbgKmCreateProcessApi, sizeof(*CreateProcessArgs));
			_This->PrivateDbgkpSendApiMessage(&m, FALSE);
			if (CreateProcessArgs->FileHandle != NULL)
			{
				ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
			}

			LoadDllArgs = &m.u.LoadDll;
			LoadDllArgs->BaseOfDll = _This->_PsSystemDllBase;
			LoadDllArgs->DebugInfoFileOffset = 0;
			LoadDllArgs->DebugInfoSize = 0;

			Teb = NULL;
			__try
			{
				NtHeaders = RtlImageNtHeader(_This->_PsSystemDllBase);
				if (NtHeaders)
				{
					LoadDllArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					LoadDllArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}

				Teb = (PTEB)PsGetThreadTeb(Thread);
				if (Teb != NULL)
				{
					Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
					wcsncpy(Teb->StaticUnicodeBuffer,
						L"ntdll.dll",
						sizeof(Teb->StaticUnicodeBuffer) / sizeof(Teb->StaticUnicodeBuffer[0]));
					LoadDllArgs->NamePointer = &Teb->NtTib.ArbitraryUserPointer;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				LoadDllArgs->DebugInfoFileOffset = 0;
				LoadDllArgs->DebugInfoSize = 0;
				LoadDllArgs->NamePointer = NULL;
			}

			InitializeObjectAttributes(
				&Obja,
				(PUNICODE_STRING)&PsNtDllPathName,
				OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
				NULL,
				NULL
			);

			Status = ZwOpenFile(
				&LoadDllArgs->FileHandle,
				(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
				&Obja,
				&IoStatusBlock,
				FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_SYNCHRONOUS_IO_NONALERT
			);

			if (!NT_SUCCESS(Status))
			{
				LoadDllArgs->FileHandle = NULL;
			}

			DBGKM_FORMAT_API_MSG(m, DbgKmLoadDllApi, sizeof(*LoadDllArgs));
			_This->PrivateDbgkpSendApiMessage(&m, TRUE);

			if (LoadDllArgs->FileHandle != NULL)
			{
				ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
			}

			if (Teb != NULL)
			{
				__try
				{
					Teb->NtTib.ArbitraryUserPointer = NULL;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {}
			}
		}
		else
		{
			CreateThreadArgs = &m.u.CreateThread;
			CreateThreadArgs->SubSystemKey = 0;
			CreateThreadArgs->StartAddress = *(void**)(_This->PrivateGetThreadStartAddress(Thread));
			//DbgPrint("111111 &CreateThreadArgs->StartAddress:%llx\n", &CreateThreadArgs->StartAddress);
			//DbgPrint("111111 CreateThreadArgs->StartAddress:%llx\n", CreateThreadArgs->StartAddress);
			//DbgPrint("111111 Thread:%llx\n", Thread);
			//DbgPrint("111111 _This->PrivateGetThreadStartAddress(Thread):%llx\n", _This->PrivateGetThreadStartAddress(Thread));
			DBGKM_FORMAT_API_MSG(m, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));
			_This->PrivateDbgkpSendApiMessage(&m, TRUE);
		}
	}

	_DbgkCreateThread func = (_DbgkCreateThread)_This->NewDbgkCreateThreadHookInfo->ori_api_address;
	if (!func)
	{
		DbgBreakPoint();
	}
	//不存在degport会被跳过 但加载回调需要正常执行
	return func(Thread, StartAddress);
}


#ifdef _AMD64_
VOID NTAPI r0_newfunc::NewDbgkMapViewOfSection(
	PEPROCESS Process,
	void* SectionObject,
	void* BaseAddress,
	unsigned int SectionOffset,
	unsigned __int64 ViewSize)
#else
VOID NTAPI NewFunc::NewDbgkMapViewOfSection(
	IN HANDLE SectionObject,
	IN PVOID BaseAddress,
	IN ULONG SectionOffset,
	IN ULONG_PTR ViewSize)
#endif // _AMD64_
{
	DBGKM_APIMSG m;
	PDBGKM_LOAD_DLL LoadDllArgs;
	PIMAGE_NT_HEADERS NtHeaders;

	PAGED_CODE();


	if (KeGetPreviousMode() == KernelMode)
	{
		return;
	}

	HANDLE temp_pid = PsGetCurrentProcessId();
	DebugInformation* debugInfo = _This->findDebugInfoByProcessId(temp_pid, temp_pid);

	if (debugInfo != NULL && debugInfo->TargetProcessId == temp_pid)
	{
		PTEB temp_teb = (PTEB)PsGetThreadTeb(PsGetCurrentThread());
		if (temp_teb == nullptr)
		{
			goto origin_func;
		}

		NTSTATUS status = _This->DbgkpSuppressDbgMsg(temp_teb);
		if (!NT_SUCCESS(status))
		{
			goto origin_func;
		}

		LoadDllArgs = &m.u.LoadDll;
		LoadDllArgs->FileHandle = _This->DbgkpSectionToFileHandle(SectionObject);
		LoadDllArgs->BaseOfDll = BaseAddress;
		LoadDllArgs->DebugInfoFileOffset = 0;
		LoadDllArgs->DebugInfoSize = 0;


		LoadDllArgs->NamePointer = temp_teb->NtTib.ArbitraryUserPointer;

		__try
		{
			NtHeaders = RtlImageNtHeader(BaseAddress);
			if (NtHeaders)
			{
				LoadDllArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				LoadDllArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LoadDllArgs->DebugInfoFileOffset = 0;
			LoadDllArgs->DebugInfoSize = 0;
		}

		DBGKM_FORMAT_API_MSG(m, DbgKmLoadDllApi, sizeof(*LoadDllArgs));

		_This->PrivateDbgkpSendApiMessage(&m, TRUE);
		if (LoadDllArgs->FileHandle != NULL)
		{
			ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
		}

		return;//以达到目的不继续往下执行了 继续执行也是直接被返回来
	}


	origin_func:
	_DbgkMapViewOfSection func = (_DbgkMapViewOfSection)_This->NewDbgkMapViewOfSectionHookInfo->ori_api_address;
	if (!func)
	{
		DbgBreakPoint();
	}
	//非目标进程
#ifdef _AMD64_
	return func(Process, SectionObject, BaseAddress, SectionOffset, ViewSize);
#else
	return func(SectionObject, BaseAddress, SectionOffset, ViewSize);
#endif // _AMD64_
}

VOID NTAPI r0_newfunc::NewDbgkUnMapViewOfSection(IN PVOID BaseAddress)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_UNLOAD_DLL UnloadDllArgs;
	PEPROCESS Process;

	PAGED_CODE();

	Process = PsGetCurrentProcess();

	if (KeGetPreviousMode() == KernelMode)
	{
		return;//直接就判断了 别往下走了
	}

	HANDLE temp_pid = PsGetCurrentProcessId();
	DebugInformation* debugInfo = _This->findDebugInfoByProcessId(temp_pid, temp_pid);

	if (debugInfo != NULL && debugInfo->TargetProcessId == temp_pid)
	{
		//同上忽略PS_CROSS_THREAD_FLAGS_HIDEFROMDBG
		UnloadDllArgs = &m.u.UnloadDll;
		UnloadDllArgs->BaseAddress = BaseAddress;
		DBGKM_FORMAT_API_MSG(m, DbgKmUnloadDllApi, sizeof(*UnloadDllArgs));
		_This->PrivateDbgkpSendApiMessage(&m, TRUE);

		return;//同上返回
	}
	
	_DbgkUnMapViewOfSection func = (_DbgkUnMapViewOfSection)_This->NewDbgkUnMapViewOfSectionHookInfo->ori_api_address;
	if (!func)
	{
		DbgBreakPoint();
	}
	//非目标进程
	return func(BaseAddress);
}

//废案 win7后通过判断createinfo 走PspInsertProcess 但dbgport流程和PSPC大致无差别
//NTSTATUS NTAPI NewFunc::NewPspCreateProcess(
//	OUT PHANDLE ProcessHandle,
//	IN ACCESS_MASK DesiredAccess,
//	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
//	IN HANDLE ParentProcess OPTIONAL,
//	IN ULONG Flags,
//	IN HANDLE SectionHandle OPTIONAL,
//	IN HANDLE DebugPort OPTIONAL,
//	IN HANDLE ExceptionPort OPTIONAL,
//	IN ULONG JobMemberLevel)
NTSTATUS NTAPI r0_newfunc::NewNtCreateUserProcess(
	PHANDLE ProcessHandle,
	PETHREAD ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	_OBJECT_ATTRIBUTES* ProcessObjectAttributes,
	_OBJECT_ATTRIBUTES* ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	_RTL_USER_PROCESS_PARAMETERS* ProcessParameters,
	void* CreateInfo,
	void* AttributeList)
{
	_NtCreateUserProcess func = (_NtCreateUserProcess)_This->NewNtCreateUserProcessHookInfo->ori_api_address;
	if (!func)
	{
		DbgBreakPoint();
	}
	//执行创建过程
	NTSTATUS status = 0;
	status = func(ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags,
		ThreadFlags,
		ProcessParameters,
		CreateInfo,
		AttributeList);

	HANDLE temp_pid = PsGetCurrentProcessId();
	DebugInformation* debugInfo = _This->findDebugInfoByProcessId(temp_pid, temp_pid);

	if (debugInfo != NULL && debugInfo->SourceProcessId == temp_pid)
	{
		//PspCreateProcess太难重写了 搞点偷懒的东西进去算了
		//最偷懒的方式是不让他createprocess 强制atttach.

		//目标成功捕获 发起进程和创建debugobj是同一个进程
		//只是查询下 就怕有注册回调打不开 就别搞这种东西恶心东西了
		PEPROCESS temp_process = nullptr;
		status = ObReferenceObjectByHandle(*ProcessHandle, 0x0400, *PsProcessType, KeGetPreviousMode(), (void**)&temp_process, NULL);
		if (!NT_SUCCESS(status))
		{
			return status;//这肯定有人在搞鬼 那没办法 要不就Int3大家一起死吧
		}
		//设置目标ID为后面的转发做匹配.
		HANDLE target_pid = PsGetProcessId(temp_process);
		debugInfo->TargetProcessId = target_pid;


		//干掉dbgport
		//干掉PEB
		//省略DbgkClearProcessDebugObject后面的obj和event清理 那东西不能清 清了我也用不了了
		*_This->PrivateGetProcessDebugPort(temp_process) = 0;
		//DbgkpMarkProcessPeb自带KeStackAttachProcess
		_This->DbgkpMarkProcessPeb(temp_process);
		//win7下DbgkpMarkProcessPeb无大变化
		//debugobj和hanlde都已经到手 prot和peb也清理完成 可以放过去了

		return status;
	}

	//不是目标进程 直接放过
	return status;
}

#pragma endregion
