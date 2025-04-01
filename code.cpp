#include <windows.h>
#include <iostream>
#include <thread>
#include <fstream>
#include <atomic>
#include <cwchar>
#include <cwchar>

#define IDI_MYICON 101
#define ID_TRAY_APP_ICON 1
#define WM_TRAYNOTIFY (WM_USER + 1)
#define IDM_EXIT 1000

std::atomic<bool> running(true);
HWND hwnd;

/*!
\file code.cpp
\brief **Код для определения профиля сети**

Открывает реестр Windows и проверяет тип сети, к которой выполнялось последнее подключение.
*/



/*!
Добавляет путь к программе в список автозагрузки windows
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
Фукция для выключения программы, если нажата кнопка "Выключить"
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
                PostQuitMessage(0);
            }
            break;
        case WM_DESTROY:
            running = false;
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}



/*!
Создание иконки на панели задач при запуске программы
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
Удаление иконки на панели задач при выключении программы
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
Получает на вход год, месяц, день, час, минуту и секунду в формате числа \n
И конвертирует их в формат времени
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
\brief Отображение MessageBox

Так-как создание MessageBox останавливает процесс выполнения программы, \n создаётся отдельный поток для предотвращения этого.
*/
DWORD WINAPI ShowUnsafeNetworkWarning(LPVOID lpParam) 
{
	MessageBoxW(NULL, L"Вы подключены к небезопасной сети!",  L"Внимание", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
    return 0;
}


/*!
\brief Получение профиля сети

Каждые десять секунд сканирует реестр виндовс \n
Получает последний профиль сети \n
Записывает в файл is_threat тип сети \n
*/
int check_win_registry() 
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	WCHAR lastProfile[255] = L"None";
	auto lastDate = makeTimePoint(0,0,0,0,0,0);
	int lastCategory = 0;
	
	int c=0;
	while (running){
		DWORD index = 0;
		WCHAR subKeyName[255];
		DWORD cbName = 255;
		
		
		int year;
		int month;
		int day;
		int hour;
		int minute;
		int second;
		
		
		HKEY hKey;
		
		LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
									L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", 
									0, 
									KEY_READ, 
									&hKey);
		if (result != ERROR_SUCCESS) {
			std::wcerr << L"Failed to open registry key. Error code: " << result << std::endl;
			return 1;
		}
		
		while (RegEnumKeyExW(hKey, index, subKeyName, &cbName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
			HKEY hSubKey;
			result = RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSubKey);
			if (result == ERROR_SUCCESS) {
				WCHAR profileName[255];
				DWORD cbData = sizeof(profileName);
				result = RegQueryValueExW(hSubKey, L"ProfileName", NULL, NULL, (LPBYTE)profileName, &cbData);
				if (result == ERROR_SUCCESS) {
					DWORD type;
					cbData = 0;
					result = RegQueryValueExW(hSubKey, L"DateLastConnected", NULL, &type, NULL, &cbData);
					if (result == ERROR_SUCCESS && type == REG_BINARY) {

						BYTE* dateData = new BYTE[cbData];
						result = RegQueryValueExW(hSubKey, L"DateLastConnected", NULL, NULL, dateData, &cbData);
						if (result == ERROR_SUCCESS) {
							
							year = int(dateData[0]+dateData[1]*256);
							month = int(dateData[2]+dateData[3]*256);
							day = int(dateData[6]+dateData[7]*256);
							hour = int(dateData[8]+dateData[9]*256);
							minute = int(dateData[10]+dateData[11]*256);
							second = int(dateData[12]+dateData[13]*256);
							
							auto date = makeTimePoint(year,month,day,hour,minute,second);
							
							DWORD category;
							RegQueryValueExW(hSubKey, L"Category", NULL, &type, (LPBYTE)&category, &cbData);
							
							if (date>lastDate or (wcscmp(profileName,lastProfile)==0 and category!=lastCategory)){
								lastDate=date;
								lastCategory=category;
								WriteConsoleW(hConsole, L"Changed Profile Name: ", 22, nullptr, nullptr);
								WriteConsoleW(hConsole, profileName, wcslen(profileName), nullptr, nullptr);
								WriteConsoleW(hConsole, "\n", 1, nullptr, nullptr);
								if (category==0 && c>0){ 
									CreateThread(NULL, 0, ShowUnsafeNetworkWarning, NULL, 0, NULL);
								}
								wcsncpy(lastProfile, profileName, 255);
							}
						} else {
							std::wcerr << L"Failed to read DateLastConnected. Error code: " << result << std::endl;
						}
					} else if (result == ERROR_FILE_NOT_FOUND) {
						std::wcerr << L"DateLastConnected not found for profile: " << profileName << std::endl;
					} else {
						std::wcerr << L"Failed to query DateLastConnected. Error code: " << result << std::endl;
					}
				}
				else{
					std::wcerr <<L"Error"<<std::endl;
				}
				RegCloseKey(hSubKey);
			}
			index++;
			cbName = 255;
			
		}
		
		if (lastCategory==0 && c==0){ 
			CreateThread(NULL, 0, ShowUnsafeNetworkWarning, NULL, 0, NULL);
		}
		
		WriteConsoleW(hConsole, L"LastProfile Name: ", wcslen(L"LastProfile Name: "), nullptr, nullptr);
		WriteConsoleW(hConsole, lastProfile, wcslen(lastProfile), nullptr, nullptr);
		WriteConsoleW(hConsole, "\n", 1, nullptr, nullptr);
		
		std::wcout <<L"Last Category: "<< lastCategory << std::endl;
		RegCloseKey(hKey);
		
		std::ofstream myFile("./is_threat", std::ios::out | std::ios::trunc);
		if (myFile.is_open()) {
			myFile << lastCategory;
			myFile.close();
		}
		
		c+=1;
		std::this_thread::sleep_for(std::chrono::seconds(10));
	}
    return 0;
}



/*!
\brief Основная функция

Запускает функцию для создания иконки на панели задач. \n
Запускает поток проверки подключения.
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
        std::cerr << "Error creating icon!" << std::endl;
        return 1;
    }
		

	
    InitTray(hwnd);

    std::thread cwrThread(check_win_registry);
	
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
	
	std::ofstream myFile("./is_threat", std::ios::out | std::ios::trunc);
	if (myFile.is_open()) {
		myFile << "1";
		myFile.close();
	}
	
    return 0;
}