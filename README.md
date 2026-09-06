# Forensic Task Manager

> **⚠️ Learning Project Disclaimer:** This project is built as a hands-on exercise to deepen my practical understanding of C++, the Win32 API, graphics rendering, and UI design patterns. Because I am actively learning, the codebase may contain bugs, inefficient algorithms, suboptimal patterns, or memory management flaws. Constructive feedback, code reviews, and issue reports are more than welcome!

## Technical Overview & Architecture

Forensic Task Manager is a custom Windows diagnostic utility that bridges low-level operating system APIs with an accelerated immediate-mode graphical user interface (GUI).

* **UI Framework:** [Dear ImGui](https://github.com/ocornut/imgui) (Docking branch enabled) utilizing a custom skinning layer to achieve a dynamic Glassmorphism aesthetic.
* **Graphics Backend:** OpenGL 3.0+ initialized directly through the Win32 window context (`wglCreateContext`).
* **System Interfacing:** Directly queries the Windows SDK (`TlHelp32.h`, `Psapi.h`, `Iphlpapi.h`, etc.) to extract process data, memory maps, threads, modules, and network connections.
* **Data Caching Pattern:** To mitigate UI stuttering caused by heavy blocking Win32 calls (such as `CreateToolhelp32Snapshot`), data is fetched and updated via a timed caching loop (`refreshTimer`) rather than every single frame.

## Core Features

* **Glassmorphic UI Engine:** Real-time adjustable transparency slider and external theme configuration loader (`LoadThemesFromFile`) with persistent local state saving.
* **Real-time Performance Graphs & Live Tracker:** Custom historical ring-buffers tracking global and per-core CPU, RAM, GPU, Disk I/O, and Network adapters activity.
* **Advanced Process Inspector & Forensics:**
  * **Virtual Memory Map:** Enumerates memory regions, states, protections, and types (`VirtualQueryEx`).
  * **Modules & Threads:** Lists loaded DLLs, base addresses, thread IDs, and base priorities.
  * **Process Control & Incident Response:** Supports termination, command-line arguments inspection, and **Process Suspension (`NtSuspendProcess`)** to freeze malicious activities or ransomware in real-time.
  * **Authenticode Code Signing Verification:** Local validation of binary digital signatures using Win32 crypto APIs to flag unsigned or untrusted executables/drivers.
  * **Process Memory Dumps:** Generates native application crash and mini-dumps (`MiniDumpWriteDump`) for offline analysis.
* **Network & Socket Forensics:**
  * Active TCP/UDP endpoint monitoring mapped directly to owner PIDs and process names.
  * **Local Port & Heuristic Intelligence:** Built-in checks flagging anomalous or commonly abused ports (e.g., potential C2 or backdoor indicators) completely offline without third-party API dependencies.
* **DLL Dependency Viewer:** Inspects native Portable Executable (PE) headers, imported APIs, and export symbols.
* **System Maintenance & Utilities:** 
  * **Windows Services Manager:** Interactive control to query, start, and stop system services.
  * **Startup & Installed Software:** Startup application optimizer, environment variables inspector, and installed software manager with uninstaller execution.
  * **Quick System Maintenance:** Built-in shortcuts for temporary file cleanup, recycle bin emptying, DNS cache flushing, Winsock/IP resets, and automated SFC/DISM system integrity scans.

## Gallery

<table>
  <tr>
    <td align="center" width="50%">
      <img width="1917" height="1044" src="https://github.com/user-attachments/assets/70202a60-979c-4caf-8e90-502a343055a2" alt="Process Inspector" /><br/>
      <sub><b>Advanced Process Inspector</b><br/><i>Virtual Memory, Modules, & TCP Endpoints</i></sub>
    </td>
    <td align="center" width="50%">
      <img src="https://github.com/user-attachments/assets/46f55bd0-3fee-4b79-af03-9932670f24ea" alt="DLL Viewer" /><br/>
      <sub><b>DLL Dependency Viewer</b><br/><i>Native PE Headers & Export Symbols</i></sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="50%">
      <img width="1919" height="1045" src="https://github.com/user-attachments/assets/956905ac-7367-47e7-b386-23bca8a7078e" alt="Live Tracker" /><br/>
      <sub><b>Live System Tracker</b><br/><i>Real-time Performance & Activity Charts</i></sub>
    </td>
    <td align="center" width="50%">
      <img width="1915" height="1044" src="https://github.com/user-attachments/assets/d3848ff9-476f-437c-8bc3-8202cd1cdae1" alt="Dump Analyzer" /><br/>
      <sub><b>Dump Analyzer</b><br/><i>Memory Dumps & Forensic Inspection</i></sub>
    </td>
  </tr>
</table>

## Known Areas for Improvement (Learning In Progress)

As an intermediate-to-advanced C++ learning project, several components are actively being refactored for better robustness:
* **RAII & Resource Safety:** Transitioning raw Win32 handle management (`CloseHandle`) to smart wrappers to completely prevent handle/memory leaks during error states.
* **Concurrency:** Refining how cached data structures are updated and safely read across timing loops to prevent race conditions.
* **Error Handling:** Replacing basic string error messages with a more unified exception or result-type pattern.

## Building and Running the Project

### Prerequisites
* Windows 10 or 11
* **MinGW-w64** (or a compatible `g++` compiler installed and added to your system PATH).

### Quick Build (PowerShell Script)
To avoid manual configuration or heavy IDE setups, you can use the provided automated PowerShell script (`build.ps1`), which compiles the source code, links the required Win32 and OpenGL libraries, and launches the application automatically.

1. Clone the repository:
   ```bash
   git clone https://github.com/Nooch98/ForensicTaskManager.git
   ```

2. Open PowerShell and navigate to the project directory:
    ```bash
    cd ForensicTaskManager
    ```

3. If script execution is restricted on your system, temporarily enable it for the current session:
    ```bash
    Set-ExecutionPolicy Unrestricted -Scope Process
    ```

4. Run the build script:
    ```bash
    .\build.ps1
    ```
