#include "framework.h"
#include "Resource.h"

#include <optional>
#include <memory>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>

#include "AppExceptions.h"
#include "SmartHandleClass.h"
#include "HDCPHelper.h"
#include "MonitorFuzz.h"

#undef GetMessage

struct HDCPStatus {
    int global;
    int local;
};

class System {
private:
    std::ofstream log_stream;
    int hdcp_last_level;
public:
    HDCPHelper hdcp;
    MonitorFuzz monitor_fuzz;

    System() : 
        log_stream("hdcp_log.txt"), 
        hdcp_last_level(-1),
        monitor_fuzz()
    {
    }

    ~System() {
    }

    void log_write(std::string msg) {
        log_stream << msg.data() << std::endl;
    }

    void hdcp_level_notify(int level) {
        if (hdcp_last_level != level) {
            std::ostringstream s;
            auto now = std::chrono::system_clock::now();
            std::time_t now_time = std::chrono::system_clock::to_time_t(now);
            auto time_buf = std::vector<char>(256);
            ctime_s(time_buf.data(), time_buf.capacity(), &now_time);
            s << time_buf.data() << " HDCP level is " << level << ".";
            log_write(s.str());
            hdcp_last_level = level;
        }
    }

    void fuzz_interval_work() {
        #ifndef HDCPENABLERPROGRAM_NOMONITORFUZZ
            try {
                monitor_fuzz.RandomlyOffsetDrive(0.1f);
            }
            catch (ProcessFailure e) {
                // Let old object deconstruct and release resources. Next time,
                // we will try to call the above function and it will do a lazy
                // initialization or fail again to this point.
                monitor_fuzz = MonitorFuzz();
            }
        #endif
    }

    int hdcp_interval_work(HDCPStatus &status) {
        try {
            int hdcp_local_pre_level = hdcp.GetLocalHDCPLevel();
            int hdcp_local_post_level = hdcp_local_pre_level;

            hdcp_level_notify(hdcp_local_pre_level);

            if (hdcp_local_pre_level == 0) {
                hdcp.RequestHDCPMaxLevel();
                hdcp_local_post_level = hdcp.GetLocalHDCPLevel();
                hdcp_level_notify(hdcp_local_post_level);
            }

            status.local = hdcp_local_post_level;
            status.global = hdcp.GetGlobalHDCPLevel();
            return 1;
        }
        catch (ProcessFailure e) {
            std::ostringstream s;
            s << "HDCP Process Failure: " << e.Message() << " [" << GetLastError() << "]";
            log_write(s.str());

            hdcp = HDCPHelper();

            status.local = -1;
            status.global = -1;
            return 0;
        }
    }
};

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

std::unique_ptr<System> g_sys;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_TEST, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_TEST));

    g_sys = std::unique_ptr<System>(new System());

    MSG msg;

    // Main message loop:
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_TEST);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_ICON1));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   //HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
   //   CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   HWND hWnd = CreateDialogW(NULL, MAKEINTRESOURCE(IDD_ABOUTBOX), NULL, WndProc);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   SetTimer(hWnd, IDT_TIMER1, 100, (TIMERPROC)NULL);
   SetTimer(hWnd, IDT_TIMER2, 5000, (TIMERPROC)NULL);

   return TRUE;
}

static void DoTimerWork(HWND hWnd) {
    HDCPStatus hdcp_status;
    int ret = g_sys->hdcp_interval_work(hdcp_status);

    char status_msg[255];

    if (ret) {
        switch (hdcp_status.global) {
        case 0:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Not Enabled");
            break;
        default:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Enabled [%i]", hdcp_status.global);
            break;
        }

        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_GLOBAL, &status_msg[0]);

        switch (hdcp_status.local) {
        case 0:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Not Enabled");
            break;
        default:
            sprintf_s(&status_msg[0], sizeof(status_msg), "HDCP Enabled [%i]", hdcp_status.local);
            break;
        }

        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_LOCAL, &status_msg[0]);
    }
    else {
        sprintf_s(&status_msg[0], sizeof(status_msg), "Initialization Failure");
        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_GLOBAL, &status_msg[0]);
        SetDlgItemTextA(hWnd, IDC_STATUS_MSG_LOCAL, &status_msg[0]);
    }
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_TIMER:
        switch (wParam) {
            case IDT_TIMER1:
                DoTimerWork(hWnd);
                break;
            case IDT_TIMER2:
                g_sys->fuzz_interval_work();
                break;
        }
        break;
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
