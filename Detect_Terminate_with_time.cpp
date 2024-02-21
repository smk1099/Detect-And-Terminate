#include <windows.h>
#include <winevt.h>
#include <WinBase.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iostream>
#include <strsafe.h>
#include <chrono>
#include <ctime>


#pragma comment(lib, "wevtapi.lib")

using namespace std;

int CheckEvent(EVT_HANDLE);
int kill_process(int);
wstring honeyPotPath;
wstring honeyPotName;
bool terminateSuccess;
chrono::system_clock::time_point detect_time;
chrono::system_clock::time_point terminate_time;

bool IsRunAsAdmin() {
    BOOL isRunAsAdmin = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            isRunAsAdmin = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return isRunAsAdmin;
}

void acquireAdmin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteEx(&sei)) {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED)
                cout << "The operation was cancelled by the user.\n";
        }
    }
    else {
        cout << "Unable to get program path, exiting...\n";
    }
}

void RunPowerShellCommand(const wstring& fullCommand) {
    STARTUPINFO startupInfo = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION processInfo;
    BOOL success = CreateProcessW(nullptr, const_cast<wchar_t*>(fullCommand.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startupInfo, &processInfo);
    if (success)
    {
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }
    else
    {
        wcout << L"Failed to execute command." << endl;
    }
}

void setHoneyPot() {
    cout << "Folder Path(ex: C:\\\\Users\\\\name\\\\folder) : ";
    wcin >> honeyPotPath;
    size_t last_index = honeyPotPath.find_last_of('\\');
    honeyPotName = honeyPotPath.substr(last_index + 1);
}

void setAudit() {
    wstring auditFlags = L"\'Success\'";
    wstring inheritanceFlags = L"\'ContainerInherit\',\'ObjectInherit\'";
    wstring accessRights = L"\'CreateFiles,WriteData,DeleteSubdirectoriesAndFiles\'";
    wstring securityIdentifier = L"\'Everyone\'";

    wstring command1 = L"powershell.exe -Command \""
        L"$folderPath = \'" + honeyPotPath + L"\';\n"
        L"$auditFlags = " + auditFlags + L";\n"
        L"$inheritanceFlags = " + inheritanceFlags + L";\n"
        L"$accessRights = " + accessRights + L";\n"
        L"$securityIdentifier = " + securityIdentifier + L";\n"
        L"$securityDescriptor = Get-Acl -Path $folderPath;\n"
        L"$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule($securityIdentifier, $accessRights, $inheritanceFlags, \'None\', $auditFlags);\n"
        L"$securityDescriptor.AddAuditRule($auditRule);\n"
        L"Set-Acl -Path $folderPath -AclObject $securityDescriptor;"
        L"\"";

    wstring command2 = L"auditpol /set /category:\"개체 액세스\" /success:enable";

    RunPowerShellCommand(command1);
    RunPowerShellCommand(command2);

}

void flush_buffer(TRACEHANDLE handle, PEVENT_TRACE_PROPERTIES ppro, PEVENT_TRACE_LOGFILEW logfile) {

    if (ControlTrace(handle, logfile->LoggerName, ppro, EVENT_TRACE_CONTROL_FLUSH) == ERROR_SUCCESS) {

        cout << "flush : success\n";
    }
    else {
        cout << "Error querying trace session: " << GetLastError() << endl;
    }
}

void call_evt_handle(EVT_HANDLE handle, int count, int iteration) {
    EVT_HANDLE* hEvents = new EVT_HANDLE[count];
    DWORD dwReturned = 0;
    bool end_point = false;
    while (EvtNext(handle, count, hEvents, INFINITE, 0, &dwReturned) && iteration > 0) {
        for (DWORD i = 0; i < dwReturned; i++) {
            if (terminateSuccess || (!end_point && CheckEvent(hEvents[i]) == 0)) {
                end_point = true;
            }
            if (hEvents[i]) EvtClose(hEvents[i]);
        }
        if (end_point) {
            break;
        }
        iteration--;
    }
    delete[] hEvents;
    if (handle) EvtClose(handle);
}


int CheckEvent(EVT_HANDLE hEvent) {
    DWORD status = ERROR_SUCCESS;
    PEVT_VARIANT pRenderedValues = NULL;
    DWORD bufferSize = 0;
    DWORD propertyCount = 0;
    LPCWSTR pwszProperties[] = { L"Event/System/EventID", L"Event/EventData/Data[@Name='ProcessId']", L"Event/EventData/Data[@Name='ObjectName']", L"Event/System/EventRecordID" };
    EVT_HANDLE hContext = EvtCreateRenderContext(sizeof(pwszProperties) / sizeof(LPCWSTR), pwszProperties, EvtRenderContextValues);

    //(4 - 4)
    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, 0, NULL, &bufferSize, &propertyCount)) {

        pRenderedValues = (PEVT_VARIANT)malloc(bufferSize);
        if (EvtRender(hContext, hEvent, EvtRenderEventValues, bufferSize, pRenderedValues, &bufferSize, &propertyCount)) {

            //(4 - 5)
            if (pRenderedValues[0].UInt16Val == 4663) {

                wstring name = pRenderedValues[2].StringVal;
                int pid = pRenderedValues[1].UInt32Val;
                wcout << L"Event ID: " << pRenderedValues[0].UInt16Val << "\n";
                wcout << L"Process ID: " << pid << "\n";
                wcout << L"Name: " << name << "\n";
                //(4 - 5 - a)
                if (name.find(honeyPotName) != std::wstring::npos) {
                    if (kill_process(pid) == -1) {
                        cout << "can not kill process.\n";
                        free(pRenderedValues);
                        return -1;
                    }
                    else {
                        //(4 - 5 - b)
                        terminateSuccess = true;
                        cout << "close process.\n";
                        free(pRenderedValues);
                        return 0;
                    }

                }
            }
        }
        free(pRenderedValues);
    }
    else {
        cout << "error! : ";
        cout << GetLastError() << endl;
    }
    return -1;
}

int kill_process(int pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        cout << "can not open process.\n";
        return -1;
    }

    if (!TerminateProcess(hProcess, 0)) {
        cout << "can not terminate process.\n";
        return -1;
    }
    terminate_time = chrono::system_clock::now();

    CloseHandle(hProcess);

    return 0;
}

void print_time(chrono::system_clock::time_point now) {
    // 현재 시간을 chrono::system_clock으로부터 얻는다

    // 시간을 시스템 시간으로 변환한다
    auto now_c = chrono::system_clock::to_time_t(now);

    // 밀리초와 마이크로초를 얻기 위해 현재 시간을 변환한다
    auto now_ms = chrono::time_point_cast<chrono::milliseconds>(now);
    auto now_us = chrono::time_point_cast<chrono::microseconds>(now);


    // 밀리초와 마이크로초만을 추출한다
    auto milliseconds = now_ms.time_since_epoch().count() % 1000;
    auto microseconds = now_us.time_since_epoch().count() % 1000;

    // tm 구조체로 시간을 변환한다
    tm tm_now;
    localtime_s(&tm_now, &now_c);

    // 시간을 포맷에 맞게 출력한다
    cout << tm_now.tm_hour << ":" << tm_now.tm_min << ":" << tm_now.tm_sec
        << ":" << milliseconds // 밀리초
        << ":" << microseconds // 마이크로초
        << endl;
}

void print_term_time() {
    cout << "Detect Time : ";
    print_time(detect_time);
    cout << "Terminate Time : ";
    print_time(terminate_time);
}


int main() {
    //(1)
    if (!IsRunAsAdmin()) {

        acquireAdmin();

    }
    else {
        //(2)
        setHoneyPot();
        setAudit();

        // (2 - 1) 
        HWND hWnd = GetConsoleWindow();
        ShowWindow(hWnd, SW_HIDE);

        EVT_HANDLE hResults;

        HANDLE hDir = CreateFileW(honeyPotPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
        CONST DWORD cbBuffer = 1024 * 1024;
        BYTE* pBuffer;
        BOOL bWatchSubtree = TRUE;
        DWORD dwNotifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION;
        DWORD bytesReturned;
        WCHAR temp[MAX_PATH] = { 0 };

        // (3)
        EVENT_TRACE_LOGFILEW logfile = { 0 };
        logfile.LoggerName = (LPWSTR)L"Eventlog-Security";
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME;

        TRACEHANDLE traceHandle = OpenTrace(&logfile);
        if (traceHandle == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
            cout << "error ! code is " << GetLastError() << "\n";
            return 0;
        }

        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
        LPBYTE buffer = new BYTE[bufferSize];
        ZeroMemory(buffer, bufferSize);

        PEVENT_TRACE_PROPERTIES ppro = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer);
        ppro->Wnode.BufferSize = bufferSize;


        FILE_NOTIFY_INFORMATION* pfni;
        BOOL fOk;
        for (;;) {
            // (4)
            pBuffer = (PBYTE)malloc(cbBuffer);

            fOk = ReadDirectoryChangesW(hDir, pBuffer, cbBuffer,
                bWatchSubtree, dwNotifyFilter, &bytesReturned, 0, 0);

            if (!fOk)
            {
                DWORD dwLastError = GetLastError();
                printf("error : %d\n", dwLastError);
                break;
            }
            pfni = (FILE_NOTIFY_INFORMATION*)pBuffer;
            StringCbCopyNW(temp, sizeof(temp), pfni->FileName, pfni->FileNameLength);


            do {

                ShowWindow(hWnd, SW_SHOWNORMAL);
                terminateSuccess = false;
                StringCbCopyNW(temp, sizeof(temp), pfni->FileName, pfni->FileNameLength);
                detect_time = chrono::system_clock::now();
                //(4 - 1)
                flush_buffer(traceHandle, ppro, &logfile);


                //(4 - 2)
                hResults = EvtQuery(NULL, L"Security", 0, EvtQueryChannelPath | EvtQueryReverseDirection);
                if (hResults == NULL) {
                    wprintf(L"EvtQuery failed with %lu\n", GetLastError());
                    return 1;
                }
                //(4 - 3)
                call_evt_handle(hResults, 10, 10);
                wprintf(L"FileName(%s)\n", temp);
                if (terminateSuccess == 1) break;
                pfni = (FILE_NOTIFY_INFORMATION*)((PBYTE)pfni + pfni->NextEntryOffset);
                if (hResults) EvtClose(hResults);
            } while (pfni->NextEntryOffset > 0);
            if (terminateSuccess == 1) {
                //DeleteFile(honeyPotPath.c_str());
                hDir = CreateFileW(honeyPotPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
                //fOk = ReadDirectoryChangesW(hDir, pBuffer, cbBuffer,
                    //bWatchSubtree, dwNotifyFilter, &bytesReturned, 0, 0);
            }
            print_term_time();
            cout << "\nPress the 'q' key to continue the detection. Else we quit\n";
            char k;
            cin >> k;
            if (k != 'q') break;
            ShowWindow(hWnd, SW_HIDE);
        }
        //(4 - 5 - b)
        //cin.ignore();


    }

    return 0;
}

