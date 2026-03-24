#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <thread>
#include <fstream>
#include <atomic>
#include <string>


#define IDI_MYICON 101
#define ID_TRAY_APP_ICON 1
#define WM_TRAYNOTIFY (WM_USER + 1)
#define IDM_EXIT 1000

std::atomic<bool> running(true);
HWND hwnd;
std::atomic<int> g_lastCategory{1};
SOCKET g_serverSocket = INVALID_SOCKET;

/*!
\file code.cpp
\brief **Code for determining network profile**
Opens the Windows registry and checks the type of network to which the last connection was made.
*/
/*!
Adds the program path to the Windows startup list
*/
int startup()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring progPath = path;
    HKEY hkey = NULL;
    LONG createStatus = RegCreateKeyW(HKEY_CURRENT_USER,
                                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                     &hkey);
   
    if (createStatus == ERROR_SUCCESS) {
        LONG status = RegSetValueExW(hkey,
                                    L"DNAlert",
                                    0,
                                    REG_SZ,
                                    (BYTE*)progPath.c_str(),
                                    (progPath.size() + 1) * sizeof(wchar_t));
       
        RegCloseKey(hkey);
    }
   
    return 0;
}

/*!
\brief Function to shut down the program if the "Exit" button is pressed
Function to shut down the program if the "Exit" button is pressed
*/
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
        case WM_TRAYNOTIFY:
            if (lParam == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, IDM_EXIT, L"Выключить");
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
                               pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            }
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDM_EXIT) {
                running = false;
                if (g_serverSocket != INVALID_SOCKET) {
                    closesocket(g_serverSocket);
                    g_serverSocket = INVALID_SOCKET;
                }
                PostQuitMessage(0);
            }
            break;
        case WM_DESTROY:
            running = false;
            if (g_serverSocket != INVALID_SOCKET) {
                closesocket(g_serverSocket);
                g_serverSocket = INVALID_SOCKET;
            }
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

/*!
Creates a tray icon when the program starts
*/
void InitTray(HWND hwnd)
{
    NOTIFYICONDATAW nid = {0};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = ID_TRAY_APP_ICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYNOTIFY;
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_MYICON));
    wcscpy(nid.szTip, L"Оповещение о небезопасном подключении к сети");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

/*!
\brief Removes the tray icon when the program exits
Removes the tray icon when the program exits
*/
void RemoveTray(HWND hwnd)
{
    NOTIFYICONDATA nid = {0};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = ID_TRAY_APP_ICON;
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

/*!
\brief time format converter
Takes year, month, day, hour, minute, and second as numbers \n
And converts them to time format
*/
std::chrono::system_clock::time_point makeTimePoint(int year, int month, int day, int hour, int minute, int second)
{
    std::tm tm = {0};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    std::time_t tt = std::mktime(&tm);
    return std::chrono::system_clock::from_time_t(tt);
}

/*!
\brief Display MessageBox
Since creating a MessageBox stops the program execution, \n a separate thread is created to prevent this.
*/
DWORD WINAPI ShowUnsafeNetworkWarning(LPVOID lpParam)
{
    MessageBoxW(NULL, L"Вы подключены к небезопасной сети!", L"Внимание", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
    return 0;
}

/*!
\brief Minimal HTTP server that only returns the network category value
*/
void runHttpServer()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return;

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    g_serverSocket = serverSocket;

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(4756);

    if (bind(serverSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(serverSocket, 5) == SOCKET_ERROR)
    {
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    while (running)
    {
        SOCKET client = accept(serverSocket, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (!running) break;
            continue;
        }

        char buf[1024]{};
        recv(client, buf, sizeof(buf)-1, 0);

        std::string request(buf);
        if (request.find("GET /is_threat") != std::string::npos)
        {
            std::string body = std::to_string(g_lastCategory.load());
            std::string response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: " + std::to_string(body.length()) + "\r\n"
                "Connection: close\r\n\r\n" + body;

            send(client, response.c_str(), response.length(), 0);
        }
        else
        {
            const char* notfound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            send(client, notfound, strlen(notfound), 0);
        }

        closesocket(client);
    }

    closesocket(serverSocket);
    WSACleanup();
}

/*!
\brief Get network profile
Scans the Windows registry every ten seconds \n
Gets the latest network profile \n
Writes to an atomic variable
*/
int check_win_registry()
{
    WCHAR lastProfile[255] = L"None";
    auto lastDate = makeTimePoint(0,0,0,0,0,0);
    int lastCategory = 0;
    bool firstRun = true; 

    while (running)
    {
        DWORD index = 0;
        WCHAR subKeyName[255];
        DWORD cbName = 255;

        int year, month, day, hour, minute, second;

        HKEY hKey;
        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
            0, KEY_READ, &hKey);

        if (result != ERROR_SUCCESS) {
            std::wcerr << L"Failed to open registry key. Error code: " << result << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(10));
            continue;
        }

        while (RegEnumKeyExW(hKey, index, subKeyName, &cbName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            HKEY hSubKey;
            result = RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSubKey);
            if (result == ERROR_SUCCESS)
            {
                WCHAR profileName[255];
                DWORD cbData = sizeof(profileName);
                result = RegQueryValueExW(hSubKey, L"ProfileName", NULL, NULL, (LPBYTE)profileName, &cbData);
                if (result == ERROR_SUCCESS)
                {
                    DWORD type;
                    cbData = 0;
                    result = RegQueryValueExW(hSubKey, L"DateLastConnected", NULL, &type, NULL, &cbData);
                    if (result == ERROR_SUCCESS && type == REG_BINARY)
                    {
                        BYTE* dateData = new BYTE[cbData];
                        result = RegQueryValueExW(hSubKey, L"DateLastConnected", NULL, NULL, dateData, &cbData);
                        if (result == ERROR_SUCCESS)
                        {
                            year   = dateData[ 0] + (dateData[ 1]<<8);
                            month  = dateData[ 2] + (dateData[ 3]<<8);
                            day    = dateData[ 6] + (dateData[ 7]<<8);
                            hour   = dateData[ 8] + (dateData[ 9]<<8);
                            minute = dateData[10] + (dateData[11]<<8);
                            second = dateData[12] + (dateData[13]<<8);

                            auto date = makeTimePoint(year, month, day, hour, minute, second);

                            DWORD category;
                            cbData = sizeof(DWORD);
                            RegQueryValueExW(hSubKey, L"Category", NULL, &type, (LPBYTE)&category, &cbData);

                            if (date > lastDate || (wcscmp(profileName, lastProfile) == 0 && category != lastCategory))
                            {
                                lastDate = date;
                                lastCategory = category;
                                wcsncpy(lastProfile, profileName, 255);

                                if (category == 0 && !firstRun) { 
                                    CreateThread(NULL, 0, ShowUnsafeNetworkWarning, NULL, 0, NULL);
                                }
                            }
                        }
                        delete[] dateData;
                    }
                }
                RegCloseKey(hSubKey);
            }
            index++;
            cbName = 255;
        }

        RegCloseKey(hKey);

        if (lastCategory == 0 && firstRun) { 
            CreateThread(NULL, 0, ShowUnsafeNetworkWarning, NULL, 0, NULL);
        }

        g_lastCategory.store(lastCategory);

        firstRun = false;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}


/*!
\brief Main function
Starts the function to create a tray icon. \n
Starts the connection monitoring thread and HTTP server.
*/
int main()
{
    startup();

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"TrayAppClass";
    RegisterClassExW(&wc);

    hwnd = CreateWindowW(L"TrayAppClass", L"TrayApp", WS_OVERLAPPEDWINDOW,
                         0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);

    if (!hwnd) {
        std::cerr << "Error creating window!" << std::endl;
        return 1;
    }

    InitTray(hwnd);

    std::thread cwrThread(check_win_registry);
    std::thread httpThread(runHttpServer);

    MessageBoxW(NULL,
                L"Приложение запущено!",
                L"Успешно",
                MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveTray(hwnd);

    cwrThread.join();
    httpThread.join();

    return 0;
}