# Forensic Task Manager

> **⚠️ Learning Project & Architectural Disclaimer:** This project is built as a hands-on exercise to deepen my practical understanding of C++, the Win32 API, graphics rendering, and UI design patterns. Because I am actively learning, the codebase embraces a **monolithic structure** with minimal early-stage optimization, featuring massive source files, basic linear execution paths, and trade-offs prioritizing feature delivery over architectural purity. Constructive feedback, code reviews, and issue reports are more than welcome!

## Technical Overview & Architecture

Forensic Task Manager is a custom Windows diagnostic utility that bridges low-level operating system APIs with an accelerated immediate-mode graphical user interface (GUI).

* **UI Framework:** [Dear ImGui](https://github.com/ocornut/imgui) (Docking branch enabled) utilizing a custom skinning layer to achieve a dynamic Glassmorphism aesthetic.
* **Graphics Backend:** OpenGL 3.0+ initialized directly through the Win32 window context (`wglCreateContext`).
* **System Interfacing:** Directly queries the Windows SDK (`TlHelp32.h`, `Psapi.h`, `Iphlpapi.h`, native NT APIs like `NtQuerySystemInformation`, etc.) to extract process data, memory maps, threads, modules, and network connections.
* **Data Caching & Asynchronous Fetching:** Heavy diagnostic and blocking operations (such as system-wide handle enumeration and module parsing) are offloaded to background worker threads (`std::thread`) with selective safe-type object name resolution, ensuring zero UI stuttering or freezes during complex process analysis.

## Core Features

* **Glassmorphic UI Engine:** Real-time adjustable transparency slider and external theme configuration loader (`LoadThemesFromFile`) with persistent local state saving.
* **Real-time Performance Graphs & Live Tracker:** Custom historical ring-buffers tracking global and per-core CPU, RAM, GPU, Disk I/O, and Network adapters activity.
* **Advanced Process Inspector & Forensics:**
  * **Parent Spoofing & Anomaly Detection:** Cross-references process paths and core parent hierarchies to flag process mimicry or unauthorized user-space binaries spawned by critical system parents.
  * **Memory Injection & Anomaly Detection:** Scans process memory space for indicators of compromise, such as unbacked executable regions, anomalous protection states, or cross-process handles indicative of DLL/shellcode injection.
  * **Handles & Advanced DLLs Inspector:** Asynchronous background extraction of process handles via native NT APIs alongside deep module validation.
  * **Virtual Memory Map & String Search:** Enumerates memory regions, states, protections, types (`VirtualQueryEx`), and supports real-time background string extraction and filtering across memory sections.
  * **Modules & Threads:** Lists loaded DLLs, base addresses, thread IDs, and base priorities.
  * **Process Control & Incident Response:** Supports termination, command-line arguments inspection, and **Process Suspension (`NtSuspendProcess`)** to freeze malicious activities or ransomware in real-time.
  * **Detailed Process Reports:** Generates comprehensive offline forensic text reports for targeted processes.
  * **Authenticode Code Signing Verification:** Local validation of binary digital signatures using Win32 crypto APIs to flag unsigned or untrusted executables/drivers.
  * **Process Memory Dumps:** Generates native application crash and mini-dumps (`MiniDumpWriteDump`) for offline analysis.
* **Digital Forensics & Artifact Parsers (DFIR):**
  * **Prefetch Analyzer:** Parses and inspects `.pf` prefetch files for execution history.
  * **MTF Parser:** Analyzes the NTFS Master File Table (MFT) for deep file system tracking.
  * **Registry Parser:** Inspects registry structures and hives.
  * **Artifact Scanner:** Automated scanner for system artifacts and indicators of compromise.
  * **Event Logs:** Parses and reviews Windows event logs.
* **Live System Imaging:** 
  * Initial implementation for creating live forensic ISO images (designed for offline analysis workflows; WinPE environment graphical adaptations in progress).
* **Network & Socket Forensics:**
  * Active TCP/UDP endpoint monitoring mapped directly to owner PIDs and process names.
  * **Local Port & Heuristic Intelligence:** Built-in checks flagging anomalous or commonly abused ports (e.g., potential C2 or backdoor indicators) completely offline without third-party API dependencies.
* **DLL Dependency Viewer:** Inspects native Portable Executable (PE) headers, imported APIs, and export symbols.
* **System Maintenance & Utilities:** 
  * **Windows Services Manager:** Interactive control to query, start, and stop system services.
  * **Startup & Installed Software:** Startup application optimizer, environment variables inspector, and installed software manager with uninstaller execution.
  * **Windows Installer Analyzer (`C:\Windows\Installer` Audit):** Deep inspection tool utilizing MSI APIs and Windows Registry cross-referencing (`UserData` and `Classes`) to safely audit cached packages (`.msi`, `.msp`) and unassociated directories, identifying active versus orphaned items for forensic storage footprint evaluation without risking system stability.
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
  <tr>
    <td align="center" width="50%">
      <img width="1919" height="1075" src="https://github.com/user-attachments/assets/4831819e-635d-4798-8014-3cb101fed847" alt="Startup Manager" /><br/>
      <sub><b>Startup Applications Manager</b><br/><i>Startup Optimization & Persistence Inspection</i></sub>
    </td>
    <td align="center" width="50%">
      <img width="1919" height="1078" src="https://github.com/user-attachments/assets/d3d135d6-e1e8-4c99-8444-b76bb046fce7" alt="Windows Services" /><br/>
      <sub><b>Windows Services Manager</b><br/><i>Service Control & State Management</i></sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="50%">
      <img width="1919" height="1079" src="https://github.com/user-attachments/assets/018a1159-26e2-4c70-a20c-5bc750d9513d" alt="Memory Virtual Map & Search Strings" /><br/>
      <sub><b>Virtual Memory Map & Search Strings</b><br/><i>Memory Regions & Real-time String Extraction</i></sub>
    </td>
    <td align="center" width="50%">
      <img width="1919" height="1078" src="https://github.com/user-attachments/assets/ef0744b4-e462-41cf-8856-7f53937b7a3d" alt="Network Socket and Connections" /><br/>
      <sub><b>Network & Socket Forensics</b><br/><i>Active Endpoints & Heuristic C2 Intelligence</i></sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="50%">
      <img width="1919" height="1079" src="https://github.com/user-attachments/assets/427af4f7-69f2-4efd-bda2-05e8135e7062" alt="Event Log" /><br/>
      <sub><b>Event Logs Parser</b><br/><i>System Event Monitoring & Review</i></sub>
    </td>
    <td align="center" width="50%">
      <img width="1918" height="1079" src="https://github.com/user-attachments/assets/78fed643-f4aa-4efb-8d10-688e90462038" alt="Prefetch Analyzer" /><br/>
      <sub><b>Prefetch Analyzer</b><br/><i>Execution History & .pf File Parsing</i></sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="50%">
      <img width="1919" height="1079" src="https://github.com/user-attachments/assets/5d5d6377-4488-4573-b51a-8c373813522e" alt="Artifact Scanner" /><br/>
      <sub><b>Artifact Scanner</b><br/><i>Automated System Artifacts & Indicators of Compromise</i></sub>
    </td>
    <td align="center" width="50%">
      <img width="1918" height="1048" src="https://github.com/user-attachments/assets/de7d97bf-be91-4a22-9afd-a34d696cd3c4" alt="Installer Folder Analyzer" /><br/>
      <sub><b>Windows Installer Analyzer</b><br/><i>Cached Package Audit & Registry Cross-Referencing</i></sub>
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
