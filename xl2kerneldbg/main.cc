/*
	WIN64驱动开发模板
	作者：Tesla.Angela
*/

//【0】包含的头文件，可以加入系统或自己定义的头文件
//#include <ntddk.h>
//#include <windef.h>
//#include <stdlib.h>
#pragma once
#include "CRT/Ntddk.hpp"
#include "CRT/NtSysAPI_Func.hpp"
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0

//#include<stdio.h>
//#include<algorithm>
//#include <vector>
//#include <iostream>
//#include <map>

#include "NativeMessage.h"
#include "r0_newfunc.h"


//【1】定义符号链接，一般来说修改为驱动的名字即可
#define	DEVICE_NAME			L"\\Device\\xl2kerneldbg"
#define LINK_NAME			L"\\DosDevices\\xl2kerneldbg"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\xl2kerneldbg"

//【2】定义驱动功能号和名字，提供接口给应用程序调用
#define IOCTL_IO_TEST		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAY_HELLO		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)


ULONG64 SectionOffset;
PLIST_ENTRY PsLoadedModuleList;
ULONG64 BaseDllNameOffset;
ULONG64 DllBaseOffset;
ULONG64 SizeOfImageOffset;
ULONG64 FlagsOffset;









//【3】驱动卸载的处理例程
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	r0_newfunc::getInstance().stopHook();

	UNICODE_STRING strLink;
	DbgPrint("[xl2kerneldbg]DriverUnload\n");
	//删除符号连接和设备
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
}

//【4】IRP_MJ_CREATE对应的处理例程，一般不用管它
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("[xl2kerneldbg]DispatchCreate\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//【5】IRP_MJ_CLOSE对应的处理例程，一般不用管它
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("[xl2kerneldbg]DispatchClose\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//【6】IRP_MJ_DEVICE_CONTROL对应的处理例程，驱动最重要的函数之一，一般走正常途径调用驱动功能的程序，都会经过这个函数
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;
	//获得IRP里的关键数据
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	//这个就是传说中的控制码
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//输入和输出的缓冲区（DeviceIoControl的InBuffer和OutBuffer都是它）
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	//EXE发送传入数据的BUFFER长度（DeviceIoControl的nInBufferSize）
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//EXE接收传出数据的BUFFER长度（DeviceIoControl的nOutBufferSize）
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//DbgPrint("[xl2kerneldbg]DispatchIoctl--------uIoControlCode:%x\n", uIoControlCode);
	r0_newfunc& nf = r0_newfunc::getInstance();
	switch (uIoControlCode)
	{
		//在这里加入接口
		case IOCTL_IO_TEST:
		{
			DWORD dw = 0;
			//输入
			memcpy(&dw, pIoBuffer, sizeof(DWORD));
			//使用
			dw++;
			//输出
			memcpy(pIoBuffer, &dw, sizeof(DWORD));
			//返回通信状态
			status = STATUS_SUCCESS;
			break;
		}
		case IOCTL_SAY_HELLO:
		{
			DbgPrint("[xl2kerneldbg]IOCTL_SAY_HELLO\n");
			status = STATUS_SUCCESS;
			break;
		}
		case IO_NtReadWriteVirtualMemory:	// 23c404
		{
			//DbgPrint("[xl2kerneldbg]IOCT----IO_NtReadWriteVirtualMemory\n");
			if (pIoBuffer != nullptr && uInSize != 0 && uOutSize != 0)
				status = nf.NewNtReadWriteVirtualMemory((Message_NtReadWriteVirtualMemory*)pIoBuffer);
			else
				status = STATUS_UNSUCCESSFUL;
			uOutSize = sizeof(Message_NtReadWriteVirtualMemory);
			break;
		}
		case IO_NtOpenProcess:
		{
			DbgPrint("[xl2kerneldbg]IOCT----IO_NtOpenProcess\n");
			if (pIoBuffer != nullptr && uInSize != 0 && uOutSize != 0)
				status = nf.NewNtOpenProcess((Message_NewNtOpenProcess*)pIoBuffer);
			else
				status = STATUS_UNSUCCESSFUL;
			uOutSize = sizeof(Message_NewNtOpenProcess);
			break;
		}
		case IO_NtCreateDebugObject:
		{
			DbgPrint("[xl2kerneldbg]IOCT----IO_NtCreateDebugObject\n");
			if (pIoBuffer != nullptr && uInSize != 0 && uOutSize != 0)
				status = nf.NewNtCreateDebugObject((Message_NewNtCreateDebugObject*)pIoBuffer);
			else
				status = STATUS_UNSUCCESSFUL;
			uOutSize = sizeof(Message_NewNtCreateDebugObject);
			break;
		}
		case IO_NtDebugActiveProcess:
		{
			DbgPrint("[xl2kerneldbg]IOCT----IO_NtDebugActiveProcess\n");
			if (pIoBuffer != nullptr && uInSize != 0 && uOutSize != 0)
				status = nf.NewNtDebugActiveProcess((Message_NewNtDebugActiveProcess*)pIoBuffer);
			else
				status = STATUS_UNSUCCESSFUL;
			uOutSize = sizeof(Message_NewNtDebugActiveProcess);
			break;
		}

	}
	//这里设定DeviceIoControl的*lpBytesReturned的值（如果通信失败则返回0长度）
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;
	//这里设定DeviceIoControl的返回值是成功还是失败
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

ULONG64 GetDllBase(PVOID PDllName) {
	ANSI_STRING DllNameA;
	UNICODE_STRING DllNameU;
	PLIST_ENTRY PDriverSection;
	PUCHAR PDriverSectionByte;
	ULONG64 ReturnBase;
	PUNICODE_STRING BaseDllName;
	ULONG64 a;

	RtlInitAnsiString(&DllNameA, (PCSZ)PDllName);
	RtlAnsiStringToUnicodeString(&DllNameU, &DllNameA, TRUE);

	PDriverSection = (PLIST_ENTRY)PsLoadedModuleList->Blink;

	//DbgBreakPoint();

	a = 1;
	ReturnBase = 666;

	//DbgPrint("[xl2kerneldbg]GetDllBase()....!\n");

	while (PDriverSection != PsLoadedModuleList) {
		PDriverSectionByte = (PUCHAR)PDriverSection;
		BaseDllName = (PUNICODE_STRING)(PDriverSectionByte + BaseDllNameOffset);
		if (RtlEqualUnicodeString(BaseDllName, &DllNameU, TRUE)) {
			ReturnBase = *((PULONG64)(PDriverSectionByte + DllBaseOffset));
			break;
		}
		else {
			PDriverSection = (PLIST_ENTRY)PDriverSection->Blink;
		}
	}
	RtlFreeUnicodeString(&DllNameU);

	return ReturnBase;
}

PLIST_ENTRY FindPsLoadedModuleList(IN PDRIVER_OBJECT DriverObject)
{
	PLDR_DATA_TABLE_ENTRY pModuleCurrent = NULL;
	PLDR_DATA_TABLE_ENTRY PsLoadedModuleList = NULL;

	if (DriverObject == NULL)
		return 0;

	pModuleCurrent = *((PLDR_DATA_TABLE_ENTRY*)(DriverObject->DriverSection));
	if (pModuleCurrent == NULL)
		return 0;

	PsLoadedModuleList = pModuleCurrent;

	while ((PLDR_DATA_TABLE_ENTRY)pModuleCurrent->InLoadOrderLinks.Flink != PsLoadedModuleList)
	{
		if (((pModuleCurrent->SizeOfImage == 0x00000000)
			&& (pModuleCurrent->FullDllName.Length == 0))
			|| (pModuleCurrent->FullDllName.Buffer == NULL) || pModuleCurrent->FullDllName.Length == 0)
		{
			return (PLIST_ENTRY)pModuleCurrent;
		}

		pModuleCurrent = (PLDR_DATA_TABLE_ENTRY)pModuleCurrent->InLoadOrderLinks.Flink;
	}

	return NULL;
}

//【7】驱动加载的处理例程，里面进行了驱动的初始化工作
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;
	//设置分发函数和卸载例程
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	//创建一个设备
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))	return status;
	//判断支持的WDM版本，其实这个已经不需要了，纯属WIN9X和WINNT并存时代的残留物
	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	//创建符号连接
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	DbgPrint("[xl2kerneldbg]DriverEntry\n");

	PsLoadedModuleList = FindPsLoadedModuleList(pDriverObj);//(PLIST_ENTRY64)GetSymAddress(L"PsLoadedModuleList");
	if (PsLoadedModuleList == 0)
	{
		DbgPrint("[xl2kerneldbg]DriverEntry call FindPsLoadedModuleList() error===========>pDriverObj:%llx,PsLoadedModuleList:%llx\n", pDriverObj, PsLoadedModuleList);
		return 1;
	}


	BaseDllNameOffset = 0x58;//GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"BaseDllName");
	SectionOffset = 0x70;//GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY",L"HashLinks");
	DllBaseOffset = 0x30;//GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"DllBase");
	SizeOfImageOffset = 0x40;//GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"SizeOfImage");
	FlagsOffset = 0x68;//GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"Flags");

	ULONG64 ntos_base_addr = GetDllBase("ntoskrnl.exe");
	DbgPrint("[xl2kerneldbg]ntoskrnl.exe base addr: %llx", ntos_base_addr);

	r0_newfunc::getInstance().init(ntos_base_addr);
	//r0_newfunc::getInstance().startHook();

	//返回加载驱动的状态（如果返回失败，驱动讲被清除出内核空间）
	return STATUS_SUCCESS;
}