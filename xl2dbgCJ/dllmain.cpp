// dllmain.cpp : 定义 DLL 应用程序的入口点。
#pragma once

#include "pch.h"

#include "hook.h"

using namespace std;

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    int ret = 0;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        cout << "dll DLL_PROCESS_ATTACH" << endl;
        if (!hook::getInstance().loadDriver())
        {
            break;
        }
        ret = hook::getInstance().startHook();
        if (ret != 0)
        {
            char msg[256] = { 0 };
            sprintf_s(msg, "hook fail %d", ret);
            MessageBoxA(0, msg, "err", 0);
            break;
        }
        break;
    case DLL_THREAD_ATTACH:
        cout << "dll DLL_THREAD_ATTACH" << endl;
        break;
    case DLL_THREAD_DETACH:
        cout << "dll DLL_THREAD_DETACH" << endl;
        break;
    case DLL_PROCESS_DETACH:    // 这个是在加载dll的主程序在卸载的时候才会调用
        cout << "dll DLL_PROCESS_DETACH" << endl;
        //MessageBoxA(0, "xl2dbgCJ dll DLL_PROCESS_DETACH", 0, 0);
        ret = hook::getInstance().exitHook();
        cout << "dll exit hook ret:" << ret << endl;
        hook::getInstance().unloadDriver();
        break;
    }
    return TRUE;
}