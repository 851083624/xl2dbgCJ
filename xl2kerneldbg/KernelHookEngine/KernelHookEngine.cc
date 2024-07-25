#pragma once
#include "KernelHookEngine.h"
#include "LDE64x64.h"


KernelHookEngine* KernelHookEngine::_This = nullptr;

KernelHookEngine& KernelHookEngine::getInstance()
{
	static KernelHookEngine instance;
	return instance;
}
KernelHookEngine::KernelHookEngine()
{
	_This = this;
	LDE_init();
	DbgPrint("KernelHookEngine...LDE_init()...\n");
}

ULONG GetPatchSize(PUCHAR Address)
{
	ULONG LenCount = 0, Len = 0;
	while (LenCount <= 14)
	{
		Len = LDE(Address, 64);
		Address = Address + Len;
		LenCount = LenCount + Len;
	}
	return LenCount;
}

KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

PVOID KernelHookEngine::HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID* Original_ApiAddress, OUT ULONG* PatchSize)
{
	KIRQL irql;
	UINT64 tmpv;
	PVOID head_n_byte, ori_func;
	UCHAR jmp_code[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	UCHAR jmp_code_orifunc[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	//How many bytes shoule be patch
	*PatchSize = GetPatchSize((PUCHAR)ApiAddress);
	//step 1: Read current data
	head_n_byte = kmalloc(*PatchSize);
	irql = WPOFFx64();
	memcpy(head_n_byte, ApiAddress, *PatchSize);
	WPONx64(irql);

	//step 2: Create ori function
	ori_func = kmalloc(*PatchSize + 14);
	RtlFillMemory(ori_func, *PatchSize + 14, 0x90);
	tmpv = (ULONG64)ApiAddress + *PatchSize;
	memcpy(jmp_code_orifunc + 6, &tmpv, 8);
	memcpy((PUCHAR)ori_func, head_n_byte, *PatchSize);
	memcpy((PUCHAR)ori_func + *PatchSize, jmp_code_orifunc, 14);
	*Original_ApiAddress = ori_func;
	//step 3: fill jmp code
	tmpv = (UINT64)Proxy_ApiAddress;
	memcpy(jmp_code + 6, &tmpv, 8);
	//step 4: Fill NOP and hook
	irql = WPOFFx64();
	RtlFillMemory(ApiAddress, *PatchSize, 0x90);
	memcpy(ApiAddress, jmp_code, 14);
	WPONx64(irql);

	//return ori code
	return head_n_byte;
}

VOID KernelHookEngine::UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize)
{
	KIRQL irql;
	irql = WPOFFx64();
	memcpy(ApiAddress, OriCode, PatchSize);
	WPONx64(irql);
}

hook_information* KernelHookEngine::hook(PVOID api_address, PVOID proxy_api_address)
{
	if (api_address == NULL || proxy_api_address == NULL)
	{
		DbgPrint("KernelHookEngine error : param null");
		return NULL;
	}

	hook_information* info = (hook_information*)ExAllocatePool(PagedPool, sizeof(hook_information));
	RtlZeroMemory(info, sizeof(hook_information));
	info->api_address = api_address;
	info->proxy_api_address = proxy_api_address;
	HookKernelApi(api_address, proxy_api_address, &info->ori_api_address, &info->patch_size);
	return info;
}

void KernelHookEngine::unhook(hook_information* hookinfo)
{
	if (hookinfo == nullptr) return;

	UnhookKernelApi(hookinfo->api_address, hookinfo->ori_api_address, hookinfo->patch_size);
	ExFreePool(hookinfo);
}