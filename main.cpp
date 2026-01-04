#include <windows.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <fstream>
#include <string>
#include <ctime>

#pragma comment(lib, "shell32.lib")

#define IDI_MYICON 101
#define ID_TRAY_APP_ICON 1001
#define WM_TRAYICON (WM_USER + 1)
#define IDM_EXIT 2001

std::atomic<bool> running(true);
HWND g_hWnd = nullptr;
const wchar_t* THREAT_FILE = L"is_threat";

// Tray
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_TRAYICON)
    {
        if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP)
        {
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_EXIT, L"Выключить DNAlerter");
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_RIGHTALIGN, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(hMenu);
        }
    }
    else if (uMsg == WM_COMMAND)
    {
        if (LOWORD(wParam) == IDM_EXIT)
        {
            running = false;
            DestroyWindow(hwnd);
        }
    }
    else if (uMsg == WM_DESTROY)
    {
        PostQuitMessage(0);
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

void AddTrayIcon()
{
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.hWnd = g_hWnd;
    nid.uID = ID_TRAY_APP_ICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_MYICON));
    wcscpy_s(nid.szTip, L"DNAlerter — защита в публичных Wi-Fi");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

void RemoveTrayIcon()
{
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.hWnd = g_hWnd;
    nid.uID = ID_TRAY_APP_ICON;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

void AddToStartup()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    HKEY hKey;
    if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, L"DNAlerter", 0, REG_SZ, (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

// Вывод лога в консоль с временем
void ConsoleLog(const std::wstring& profileName, bool isPublic)
{
    time_t now = time(0);
    char timeStr[26];
    ctime_s(timeStr, sizeof(timeStr), &now);
    std::string time(timeStr);
    time.pop_back(); // убрать \n

    std::wcout << L"[" << std::wstring(time.begin(), time.end()) << L"] "
               << L"Сеть: \"" << profileName << L"\" → "
               << (isPublic ? L"ОБЩЕДОСТУПНАЯ (опасно)" : L"ЧАСТНАЯ (безопасно)")
               << std::endl;
}

// Определение текущей сети по последней дате подключения
struct NetworkInfo {
    std::wstring name;
    DWORD category = 0;
    FILETIME lastConnected = {0};
};

NetworkInfo GetCurrentNetwork()
{
    NetworkInfo current;
    current.lastConnected.dwHighDateTime = 0;

    HKEY hProfiles;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
                      0, KEY_READ, &hProfiles) != ERROR_SUCCESS)
        return current;

    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD nameSize = 256;

    while (RegEnumKeyExW(hProfiles, index++, subKeyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        HKEY hSub;
        if (RegOpenKeyExW(hProfiles, subKeyName, 0, KEY_READ, &hSub) == ERROR_SUCCESS)
        {
            wchar_t profileName[256] = L"";
            DWORD size = sizeof(profileName);
            RegQueryValueExW(hSub, L"ProfileName", NULL, NULL, (BYTE*)profileName, &size);

            FILETIME ft = {0};
            size = sizeof(ft);
            if (RegQueryValueExW(hSub, L"DateLastConnected", NULL, NULL, (BYTE*)&ft, &size) == ERROR_SUCCESS)
            {
                DWORD category = 0;
                size = sizeof(category);
                RegQueryValueExW(hSub, L"Category", NULL, NULL, (BYTE*)&category, &size);

                if (CompareFileTime(&ft, &current.lastConnected) > 0)
                {
                    current.name = profileName;
                    current.category = category;
                    current.lastConnected = ft;
                }
            }
            RegCloseKey(hSub);
        }
        nameSize = 256;
    }
    RegCloseKey(hProfiles);
    return current;
}

void CheckNetworkLoop()
{
    std::wstring lastName = L"";
    bool lastWasPublic = false;

    while (running)
    {
        NetworkInfo net = GetCurrentNetwork();

        if (!net.name.empty())
        {
            bool isPublic = (net.category == 0);  // 0 = Public

            // Записываем статус для расширения
            std::ofstream file("is_threat", std::ios::trunc);
            if (file.is_open())
            {
                file << (isPublic ? "0" : "1");
                file.close();
            }

            // Логируем в консоль только при изменении
            if (net.name != lastName || isPublic != lastWasPublic)
            {
                ConsoleLog(net.name, isPublic);

                if (isPublic && !lastWasPublic)
                {
                    MessageBoxW(NULL,
                        (L"Подключено к общедоступной сети:\n\"" + net.name + L"\"\n\nНе вводите пароли и личные данные!").c_str(),
                        L"DNAlerter — Внимание!", MB_OK | MB_ICONWARNING);
                }

                lastName = net.name;
                lastWasPublic = isPublic;
            }
        }
        else
        {
            std::wcout << L"[Нет активных сетевых профилей]" << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(6));
    }
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Открываем консоль для отладки (уберём в финальной версии)
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
    std::wcout << L"DNAlerter запущен. Логи в консоли." << std::endl;

    AddToStartup();

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"DNAlerterClass";
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(0, L"DNAlerterClass", L"DNAlerter", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    if (!g_hWnd) return 1;

    AddTrayIcon();

    std::thread networkThread(CheckNetworkLoop);

    MessageBoxW(NULL, L"DNAlerter запущен и работает в фоне.\nДля отладки открыта консоль.", L"Готово", MB_OK | MB_ICONINFORMATION);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    running = false;
    networkThread.join();

    RemoveTrayIcon();

    std::ofstream file("is_threat", std::ios::trunc);
    if (file.is_open()) { file << "1"; file.close(); }

    FreeConsole();  // Закрываем консоль при выходе

    return 0;
}