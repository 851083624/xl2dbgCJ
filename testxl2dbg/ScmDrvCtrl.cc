#include <iostream>
#include "ScmDrvCtrl.h"
#include <winioctl.h>

ScmDrvCtrl* ScmDrvCtrl::_This = nullptr;

ScmDrvCtrl& ScmDrvCtrl::getInstance()
{
	static ScmDrvCtrl instance;
	return instance;
}
ScmDrvCtrl::ScmDrvCtrl()
{
	_This = this;
	m_pSysPath = NULL;
	m_pServiceName = NULL;
	m_pDisplayName = NULL;
	m_hSCManager = NULL;
	m_hService = NULL;
	m_hDriver = INVALID_HANDLE_VALUE;
}


//ScmDrvCtrl::~ScmDrvCtrl()
//{
//	CloseServiceHandle(m_hService);
//	CloseServiceHandle(m_hSCManager);
//	CloseHandle(m_hDriver);
//}

BOOL ScmDrvCtrl::GetSvcHandle()
{
	m_hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == m_hSCManager)
	{
		m_dwLastError = GetLastError();
		return FALSE;
	}
	m_hService = OpenServiceA(m_hSCManager, m_pServiceName, SERVICE_ALL_ACCESS);
	if (NULL == m_hService)
	{
		CloseServiceHandle(m_hSCManager);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL ScmDrvCtrl::Install()
{
	m_hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == m_hSCManager)
	{
		m_dwLastError = GetLastError();
		return FALSE;
	}
	m_hService = CreateServiceA(m_hSCManager, m_pServiceName, m_pDisplayName,
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		m_pSysPath, NULL, NULL, NULL, NULL, NULL);
	if (NULL == m_hService)
	{
		m_dwLastError = GetLastError();
		if (ERROR_SERVICE_EXISTS == m_dwLastError)
		{
			m_hService = OpenServiceA(m_hSCManager, m_pServiceName, SERVICE_ALL_ACCESS);
			if (NULL == m_hService)
			{
				CloseServiceHandle(m_hSCManager);
				return FALSE;
			}
		}
		else
		{
			CloseServiceHandle(m_hSCManager);
			return FALSE;
		}
	}
	return TRUE;
}

BOOL ScmDrvCtrl::Start()
{
	if (!StartServiceA(m_hService, NULL, NULL))
	{
		m_dwLastError = GetLastError();
		return FALSE;
	}
	return TRUE;
}

BOOL ScmDrvCtrl::Stop()
{
	SERVICE_STATUS ss;
	GetSvcHandle();
	if (!ControlService(m_hService, SERVICE_CONTROL_STOP, &ss))
	{
		m_dwLastError = GetLastError();
		return FALSE;
	}
	return TRUE;

}

BOOL ScmDrvCtrl::Remove()
{
	GetSvcHandle();
	if (!DeleteService(m_hService))
	{
		m_dwLastError = GetLastError();
		return FALSE;
	}
	return TRUE;
}

BOOL ScmDrvCtrl::Open()//example: \\\\.\\xxoo
{
	if (m_hDriver != INVALID_HANDLE_VALUE)
		return TRUE;
	m_hDriver = CreateFileA(_This->pLinkName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (m_hDriver != INVALID_HANDLE_VALUE)
		return TRUE;
	else
		return FALSE;
}

BOOL ScmDrvCtrl::IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD* RealRetBytes)
{
	DWORD dw;
	BOOL b = DeviceIoControl(m_hDriver, CTL_CODE_GEN(dwIoCode), InBuff, InBuffLen, OutBuff, OutBuffLen, &dw, NULL);
	if (RealRetBytes)
		*RealRetBytes = dw;
	return b;
}

DWORD ScmDrvCtrl::CTL_CODE_GEN(DWORD lngFunction)
{
	return (FILE_DEVICE_UNKNOWN * 65536) | (FILE_ANY_ACCESS * 16384) | (lngFunction * 4) | METHOD_BUFFERED;
}

void ScmDrvCtrl::GetAppPath(char* szCurFile) //×îºó´øÐ±¸Ü
{
	GetModuleFileNameA(0, szCurFile, MAX_PATH);
	for (SIZE_T i = strlen(szCurFile) - 1; i >= 0; i--)
	{
		if (szCurFile[i] == '\\')
		{
			szCurFile[i + 1] = '\0';
			break;
		}
	}
}