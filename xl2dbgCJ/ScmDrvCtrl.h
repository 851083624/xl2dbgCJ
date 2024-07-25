#pragma once
#include <Windows.h>
/*============================
Drvier Control Class (SCM way)
============================*/

#pragma comment(lib,"advapi32.lib")

class ScmDrvCtrl
{
public:
	static ScmDrvCtrl& getInstance();
	ScmDrvCtrl(const ScmDrvCtrl&) = delete;
	ScmDrvCtrl& operator=(const ScmDrvCtrl&) = delete;
private:
	ScmDrvCtrl();

public:
	static ScmDrvCtrl* _This;

public:
	DWORD m_dwLastError;
	const char* m_pSysPath;
	const char* m_pServiceName;
	const char* m_pDisplayName;
	HANDLE m_hDriver;
	SC_HANDLE m_hSCManager;
	SC_HANDLE m_hService;
public:
	const char* pLinkName;
public:
	BOOL Install();
	BOOL Start();
	BOOL Stop();
	BOOL Remove();
	BOOL Open();
	BOOL IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD* RealRetBytes);

public:
	void GetAppPath(char* szCurFile);

private:
	BOOL GetSvcHandle();
	DWORD CTL_CODE_GEN(DWORD lngFunction);
protected:
	//null
};

