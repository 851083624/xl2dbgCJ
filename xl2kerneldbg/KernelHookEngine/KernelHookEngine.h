#pragma once
#include <ntifs.h>
#include <intrin.h>


#pragma pack(1)
struct hook_information
{
    PVOID api_address;
    PVOID proxy_api_address;
    PVOID ori_api_address;
    ULONG patch_size;
};

#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')

class KernelHookEngine
{
public:
    static KernelHookEngine& getInstance();
    static KernelHookEngine* _This;

    KernelHookEngine(const KernelHookEngine&) = delete;
    KernelHookEngine& operator=(const KernelHookEngine&) = delete;

private:
    KernelHookEngine();

private:
    static PVOID HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID* Original_ApiAddress, OUT ULONG* PatchSize);
    static VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize);

public:
    static hook_information* hook(PVOID api_address, PVOID proxy_api_address);
    static void unhook(hook_information* hookinfo);
};

