// testxl2dbg.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<Windows.h>
#include "./ScmDrvCtrl.h"

#include <Shlwapi.h>
#include <TlHelp32.h>

using namespace std;

DWORD GetPIDForProcess(const char * processName)
{
    BOOL            working = 0;
    PROCESSENTRY32 lppe = { 0 };
    DWORD            targetPid = 0;

    wchar_t str1[256] = {0};
    wsprintf(str1, L"%hs", processName);

    //wprintf(L"%ws", str1);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot)
    {
        lppe.dwSize = sizeof(lppe);
        working = Process32First(hSnapshot, &lppe);
        while (working)
        {
            if (std::wstring(lppe.szExeFile) == str1)
            {
                targetPid = lppe.th32ProcessID;
                break;
            }
            working = Process32Next(hSnapshot, &lppe);
        }
    }
    CloseHandle(hSnapshot);
    return targetPid;
}

void DebugLoop2(DWORD dwProcessID)
{

    BOOL stopDebug;

    // Attach Process

    if (!DebugActiveProcess(dwProcessID))
    {
        printf("DebugActiveProcess(%d) failed!!!\n"
            "Error Code = %d\n", dwProcessID, GetLastError());
        return;
    }

    printf("DebugActiveProcess ok..\n");

    //goto over;

    /*if (!DebugActiveProcessStop(dwProcessID))
    {
        printf("DebugActiveProcessStop(%d) failed!!!\n"
            "Error Code = %d\n", dwProcessID, GetLastError());
    }
    else
        printf("DebugActiveProcessStop ok..\n");

    return;*/


    DEBUG_EVENT DebugEvent;
    DWORD dwContinueStatus;

    // 等待调试事件
    while (WaitForDebugEvent(&DebugEvent, INFINITE))
    {
        dwContinueStatus = DBG_CONTINUE;

        cout << DebugEvent.dwDebugEventCode << endl;
        //dwDebugEventCode是用来区分不同事件的事件码，用来判断事件

        // 调试事件为创建进程
        //if (CREATE_PROCESS_DEBUG_EVENT == DebugEvent.dwDebugEventCode)
        //{
        //    OnCreateProcessDebugEvent(&DebugEvent);
        //}
        // 调试事件为创建线程
        if (CREATE_THREAD_DEBUG_EVENT == DebugEvent.dwDebugEventCode)
        {
            //OnCreateProcessDebugEvent(&DebugEvent);
            cout << "接收到创建线程事件=====>" << hex << DebugEvent.u.CreateThread.lpStartAddress << endl;
            //system("pause");
        }
        // 调试事件
        if (EXCEPTION_DEBUG_EVENT == DebugEvent.dwDebugEventCode)
        {
            //if (OnExceptionDebugEvent(&DebugEvent))
            //    continue;
            cout << "接收到调试事件=====>ExceptionAddress:" << DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress << endl;
            cout << "dwProcessId=====>" << DebugEvent.dwProcessId << endl;
            cout << "dwThreadId=====>" << DebugEvent.dwThreadId << endl;
            system("pause");
        }
        //// 调试进程退出
        //else if (EXIT_PROCESS_DEBUG_EVENT == DebugEvent.dwDebugEventCode)
        //{
        //
        //    break;
        //}

        //system("pause");
        //cout << "x" << endl;
        ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, dwContinueStatus);
        /*cout << "is stop debug ?" << endl;
        cin >> stopDebug;
        if (stopDebug)
        {
            if (!DebugActiveProcessStop(dwProcessID))
            {
                printf("DebugActiveProcessStop(%d) failed!!!\n"
                    "Error Code = %d\n", dwProcessID, GetLastError());
            }
            else
                printf("DebugActiveProcessStop ok..\n");
        }*/
    }

over:
    cout << "DebugLoop2() over...." << endl;
}


int main(int paramCount,char** param)
{
    cout << "PID:0x" << hex << GetCurrentProcessId() << ", " << dec << GetCurrentProcessId() << endl;
    cout << "DebugLoop2 addr:" << hex << DebugLoop2 << endl;

    bool b;
    char msg[256] = { 0 };

    DWORD dwProcessID;

    char instr[256] = { 0 };

    //printf("%d\n", paramCount);
    //printf("%llx\n", param);
    //printf("%s\n", param[0]);
    //printf("%s\n", param[1]);

    if (param[1]==NULL || _stricmp(param[1], "") == 0)
    {

        const char* processName = "ConsDemo20240706.exe";
        const char* processName2 = "mengling-x86_64.exe";
        const char* zzName = processName;

        dwProcessID = GetPIDForProcess(processName);
        if (dwProcessID == 0) {
            dwProcessID = GetPIDForProcess(processName2);
            zzName = processName2;
        }
        if (dwProcessID == 0)
        {
            //cout << processName << "  find pid fail!" << endl;
            //system("pause");
            //return 0;

            cout << "Input ProcessID" << endl;
            cin >> instr;
            if (_stricmp(instr, "q") == 0) return 0;
            dwProcessID = atoi(instr);
        } else {
            cout << zzName << "  find pid ok:" << dwProcessID << endl;
            system("pause");
        }
        
    }
    else
    {
        dwProcessID = atoi((const char*)param[1]);
    }

    cout << "debug dwProcessID:" << dwProcessID << endl;

    //ScmDrvCtrl* dc = ScmDrvCtrl::getInstance()._This;
    //const char* sysFileName = "xl2kerneldbg.sys";
    ////设置驱动名称
    //char filePath[MAX_PATH] = { 0 };
    //dc->GetAppPath(filePath);
    //strcat_s(filePath, sysFileName);
    //dc->m_pSysPath = filePath;
    //dc->m_pDisplayName = "xl2kerneldbg";
    //dc->m_pServiceName = "xl2kerneldbg";
    //dc->pLinkName = "\\\\.\\xl2kerneldbg";

    ////安装并启动驱动
    //b = dc->Install();
    //cout << "driver install b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
    //system("pause");
    //if (!b)
    //{
    //    sprintf_s(msg, "Driver Install fail, code:%x", GetLastError());
    //    MessageBoxA(0, msg, "err", 0);
    //}
    //b = dc->Start();
    //cout << "driver Start b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
    //system("pause");
    //if (!b)
    //{
    //    sprintf_s(msg, "Driver Start fail, code:%x", GetLastError());
    //    MessageBoxA(0, msg, "err", 0);
    //}
    //printf("LoadDriver=%d\n", b);


    ///////////////////////////////////////////////////////////////
    //system("pause");
     
    HMODULE hModule = LoadLibraryA("xl2dbgCJ.dll");
    cout << "load library xl2dbgCJ.dll  hModule:" << hModule << endl;

    cout << "DebugLoop2 addr:" << hex << DebugLoop2 << endl;
    //TestDebugger();
    if (hModule != NULL) DebugLoop2(dwProcessID);
    //system("pause");

    b = FreeLibrary(hModule);
    cout << "free Libiary xl2dbgCJ.dll b:" << b << endl;
    //////////////////////////////////////////////////////////////


    //b = dc->Open();
    //cout << "driver open b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
    //system("pause");
    //if (!b)
    //{
    //	sprintf_s(msg, "Driver Open fail, code:%x", GetLastError());
    //	MessageBoxA(0, msg, "err", 0);
    //	return b;
    //}

    //DWORD realRetBytes = 0;
    //b = dc->IoControl(0x801, 0, 0, 0, 0, &realRetBytes);
    //cout << "driver say hello b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
    //system("pause");

    ////关闭符号链接句柄  如果已经打开了不关闭句柄就停止卸载的话,程序是会返回成功,但是不会立即生效的,
    ////它会在程序退出时,然后停止卸载,并且下一次重新安装时会失败,解决办法是调用一次停止,会提示失败驱动未启动,不过没关系,然后就可以安装了
    ////还有一点需要说明,一个程序中不能打开启动2次,第二次安装不了,关闭了句柄也是无效,如果停止卸载了后想要继续重新安装启动,则需要重新打开程序(待解决)
    //b = CloseHandle(dc->m_hDriver);
    //cout << "driver close b:" << b << endl;
    //system("pause");


    //b = dc->Stop();
    //cout << "driver stop b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
    //system("pause");

    //b = dc->Remove();
    //cout << "driver remove b:" << b << ", lastErrCode:" << dc->m_dwLastError << endl;
    //system("pause");

    cout << "testxl2dbg.exe exec over" << endl;
    system("pause");

}
