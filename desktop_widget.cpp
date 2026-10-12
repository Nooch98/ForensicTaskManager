#include "desktop_widget.h"
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_opengl3.h>
#include <GL/gl.h>
#include <vector>
#include <string>
#include <algorithm>
#include <windows.h>
#include <psapi.h>
#include <unordered_map>

#pragma comment(lib, "psapi.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

extern float GetGlobalCpuUsage();

struct WidgetProcessInfo {
    DWORD pid;
    std::string name;
    float cpuUsage;
    float ramMB;
};

struct ProcessTimeRecord {
    ULONGLONG lastSystemTime;
    ULONGLONG lastProcessTime;
};
static std::unordered_map<DWORD, ProcessTimeRecord> g_processTimeMap;

static ULONGLONG FileTimeToULike(const FILETIME& ft) {
    ULARGE_INTEGER lui;
    lui.LowPart = ft.dwLowDateTime;
    lui.HighPart = ft.dwHighDateTime;
    return lui.QuadPart;
}

static float GetRealRAMUsagePercent() {
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        return (float)status.dwMemoryLoad;
    }
    return 0.0f;
}

static std::vector<WidgetProcessInfo> GetRealProcesses() {
    std::vector<WidgetProcessInfo> list;
    DWORD processes[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        return list;
    }
    cProcesses = cbNeeded / sizeof(DWORD);

    FILETIME sysIdle, sysKernel, sysUser;
    if (!GetSystemTimes(&sysIdle, &sysKernel, &sysUser)) {
        return list;
    }
    ULONGLONG currentKernelTime = FileTimeToULike(sysKernel);
    ULONGLONG currentUserTime = FileTimeToULike(sysUser);
    ULONGLONG currentSystemTime = currentKernelTime + currentUserTime;

    std::unordered_map<DWORD, ProcessTimeRecord> newTimeMap;

    for (DWORD i = 0; i < cProcesses; i++) {
        DWORD processID = processes[i];
        if (processID == 0 || processID == 4) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (hProcess) {
            char szProcessName[MAX_PATH] = "<unknown>";
            HMODULE hMod;
            DWORD cbNeededMod;
            if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &cbNeededMod, LIST_MODULES_ALL)) {
                GetModuleBaseNameA(hProcess, hMod, szProcessName, sizeof(szProcessName));
            } else {
                GetProcessImageFileNameA(hProcess, szProcessName, sizeof(szProcessName));
                char* lastSlash = strrchr(szProcessName, '\\');
                if (lastSlash) {
                    strcpy_s(szProcessName, sizeof(szProcessName), lastSlash + 1);
                }
            }

            PROCESS_MEMORY_COUNTERS_EX pmc;
            float ramMb = 0.0f;
            if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                ramMb = (float)(pmc.WorkingSetSize) / (1024.0f * 1024.0f);
            }

            float cpuPercent = 0.0f;
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                ULONGLONG procTime = FileTimeToULike(kernelTime) + FileTimeToULike(userTime);
                
                auto it = g_processTimeMap.find(processID);
                if (it != g_processTimeMap.end()) {
                    ULONGLONG systemTimeDelta = currentSystemTime - it->second.lastSystemTime;
                    ULONGLONG processTimeDelta = procTime - it->second.lastProcessTime;

                    if (systemTimeDelta > 0) {
                        SYSTEM_INFO sysInfo;
                        GetSystemInfo(&sysInfo);
                        cpuPercent = (float)((double)processTimeDelta / (double)systemTimeDelta) * 100.0f * (float)sysInfo.dwNumberOfProcessors;
                        if (cpuPercent > 100.0f) cpuPercent = 100.0f;
                    }
                }
                newTimeMap[processID] = { currentSystemTime, procTime };
            }

            list.push_back({processID, std::string(szProcessName), cpuPercent, ramMb});
            CloseHandle(hProcess);
        }
    }

    g_processTimeMap = newTimeMap;
    return list;
}

static LRESULT CALLBACK WidgetWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;
    case WM_NCHITTEST: {
        POINT pt = { (short)LOWORD(lParam), (short)HIWORD(lParam) };
        ScreenToClient(hWnd, &pt);
        RECT rc;
        GetClientRect(hWnd, &rc);
        int border = 12;
        if (pt.x >= rc.right - border && pt.y >= rc.bottom - border) return HTBOTTOMRIGHT;
        if (pt.x >= rc.right - border) return HTRIGHT;
        if (pt.y >= rc.bottom - border) return HTBOTTOM;
        return HTCAPTION;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void RunStandaloneWidget(HINSTANCE hInstance, HWND hMainWnd) {
    DWORD parentPid = 0;
    char* cmdLine = GetCommandLineA();
    char* p = strstr(cmdLine, "--parent-pid");
    if (p) {
        parentPid = (DWORD)atoi(p + 12);
    }

    HANDLE hParent = NULL;
    if (parentPid != 0) {
        hParent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    }

    const wchar_t* className = L"NexusGlassWidgetClass";
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WidgetWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = className;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_LAYERED, 
        className, 
        L"Forensic System Widget", 
        WS_POPUP | WS_VISIBLE | WS_SIZEBOX, 
        200, 200, 320, 560, 
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) {
        if (hParent) CloseHandle(hParent);
        return;
    }

    SetLayeredWindowAttributes(hwnd, 0, 235, LWA_ALPHA);

    HDC hDC = GetDC(hwnd);
    PIXELFORMATDESCRIPTOR pfd = { sizeof(PIXELFORMATDESCRIPTOR), 1, PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, PFD_TYPE_RGBA, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 8, 0, PFD_MAIN_PLANE, 0, 0, 0, 0 };
    int format = ChoosePixelFormat(hDC, &pfd);
    SetPixelFormat(hDC, format, &pfd);
    HGLRC hRC = wglCreateContext(hDC);
    wglMakeCurrent(hDC, hRC);

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 8.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.08f, 0.12f, 0.85f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.2f, 0.7f, 1.0f, 0.5f);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplOpenGL3_Init("#version 130");

    ULONGLONG lastCpuUpdate = 0;
    ULONGLONG lastProcUpdate = 0;
    float cachedCpuVal = 0.0f;
    std::vector<WidgetProcessInfo> cachedProcs;
    static int sortMode = 0;

    bool running = true;
    while (running) {
        if (hParent) {
            if (WaitForSingleObject(hParent, 0) == WAIT_OBJECT_0) {
                running = false;
            }
        }

        MSG msg;
        while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) {
                running = false;
            }
        }
        if (!running) break;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);
        
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;

        if (ImGui::Begin("WidgetMain", nullptr, window_flags)) {
            
            ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "SYSTEM WIDGET");
            ImGui::Separator();

            ULONGLONG currentTime = GetTickCount64();
            if (currentTime - lastCpuUpdate > 500) {
                cachedCpuVal = GetGlobalCpuUsage();
                lastCpuUpdate = currentTime;
            }

            if (currentTime - lastProcUpdate > 1000 || cachedProcs.empty()) {
                cachedProcs = GetRealProcesses();
                lastProcUpdate = currentTime;
            }

            float ramVal = GetRealRAMUsagePercent();
            float gpuVal = cachedCpuVal * 0.4f;
            float netVal = 0.1f;  
            float diskVal = 0.5f; 

            ImGui::Text("CPU: %.1f%%", cachedCpuVal);
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.2f, 0.6f, 1.0f, 1.0f));
            ImGui::ProgressBar(cachedCpuVal / 100.0f, ImVec2(-1.0f, 12.0f), "");
            ImGui::PopStyleColor();

            ImGui::Text("RAM: %.1f%%", ramVal);
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.8f, 0.4f, 1.0f, 1.0f));
            ImGui::ProgressBar(ramVal / 100.0f, ImVec2(-1.0f, 12.0f), "");
            ImGui::PopStyleColor();

            ImGui::Text("GPU: %.1f%%", gpuVal);
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.2f, 0.9f, 0.4f, 1.0f));
            ImGui::ProgressBar(gpuVal / 100.0f, ImVec2(-1.0f, 12.0f), "");
            ImGui::PopStyleColor();

            ImGui::Text("NET: %.1f KB/s", netVal);
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.9f, 0.7f, 0.2f, 1.0f));
            ImGui::ProgressBar(netVal / 1000.0f, ImVec2(-1.0f, 12.0f), "");
            ImGui::PopStyleColor();

            ImGui::Text("DISK: %.1f MB/s", diskVal);
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
            ImGui::ProgressBar(diskVal / 50.0f, ImVec2(-1.0f, 12.0f), "");
            ImGui::PopStyleColor();

            ImGui::Separator();

            std::vector<WidgetProcessInfo> procs = cachedProcs;
            if (sortMode == 0) {
                std::sort(procs.begin(), procs.end(), [](const auto& a, const auto& b) { return a.ramMB > b.ramMB; });
            } else {
                std::sort(procs.begin(), procs.end(), [](const auto& a, const auto& b) { return a.cpuUsage > b.cpuUsage; });
            }

            if (ImGui::BeginTable("WidgetTable", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("CPU", ImGuiTableColumnFlags_WidthFixed, 55);
                ImGui::TableSetupColumn("RAM", ImGuiTableColumnFlags_WidthFixed, 60);

                ImGui::TableNextRow(ImGuiTableRowFlags_Headers);
                
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("Process");

                ImGui::TableSetColumnIndex(1);
                if (ImGui::SmallButton(sortMode == 1 ? "CPU v" : "CPU")) {
                    sortMode = 1;
                }

                ImGui::TableSetColumnIndex(2);
                if (ImGui::SmallButton(sortMode == 0 ? "RAM v" : "RAM")) {
                    sortMode = 0;
                }

                int count = 0;
                for (auto& p : procs) {
                    if (count++ >= 8) break; 
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::Text("%s", p.name.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::Text("%.1f%%", p.cpuUsage);
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%.0fM", p.ramMB);
                }
                ImGui::EndTable();
            }
        }
        ImGui::End();

        ImGui::Render();
        RECT rect;
        GetClientRect(hwnd, &rect);
        glViewport(0, 0, rect.right - rect.left, rect.bottom - rect.top);
        glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SwapBuffers(hDC);

        Sleep(15);
    }

    if (hParent) {
        CloseHandle(hParent);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(hRC);
    ReleaseDC(hwnd, hDC);
    DestroyWindow(hwnd);
}