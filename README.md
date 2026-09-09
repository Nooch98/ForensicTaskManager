# Forensic Task Manager

> **⚠️ Learning Project Disclaimer:** This project is built as a hands-on exercise to deepen my practical understanding of C++, the Win32 API, graphics rendering, and UI design patterns. Because I am actively learning, the codebase may contain bugs, inefficient algorithms, suboptimal patterns, or memory management flaws. Constructive feedback, code reviews, and issue reports are more than welcome!

## Technical Overview & Architecture

Forensic Task Manager is a custom Windows diagnostic utility that bridges low-level operating system APIs with an accelerated immediate-mode graphical user interface (GUI). 

The application utilizes Dear ImGui with the docking branch enabled, paired with a custom skinning layer to achieve a dynamic Glassmorphism aesthetic. Graphics rendering is handled via OpenGL 3.0+, initialized directly through the native Win32 window context using `wglCreateContext`. To interface with the OS, the program queries the Windows SDK (`TlHelp32.h`, `Psapi.h`, `Iphlpapi.h`, etc.) to extract processes, memory layouts, threads, modules, and network connections. Furthermore, to mitigate UI stuttering caused by heavy blocking Win32 calls such as `CreateToolhelp32Snapshot`, data is fetched asynchronously and updated via a timed caching loop (`refreshTimer`) rather than every single frame.

## Core Features & Capabilities

### User Interface & Performance
The user interface features a real-time adjustable transparency slider and an external theme configuration loader (`LoadThemesFromFile`) with persistent local state saving. Performance tracking is driven by custom historical ring-buffers that monitor global and per-core CPU usage, RAM allocation, GPU metrics, Disk I/O, and network adapter activity simultaneously.

### Advanced Process Inspector & Forensics
At the heart of the diagnostic suite is a robust process inspector capable of deep system interrogation. It enumerates virtual memory regions, states, protections, and types via `VirtualQueryEx`, complemented by real-time background string extraction and filtering across memory sections. Users can inspect loaded DLL modules, base addresses, thread IDs, and base priorities. For incident response, the tool supports process termination, command-line inspection, process memory dumping (`MiniDumpWriteDump`), local Authenticode digital signature validation using Win32 crypto APIs, and real-time process suspension (`NtSuspendProcess`) to freeze malicious activities or ransomware on the spot. It also generates comprehensive offline forensic text reports for targeted processes.

### Digital Forensics & Artifact Parsers (DFIR)
The utility incorporates specialized modules for digital forensics and incident response. This includes a Prefetch Analyzer that parses and inspects `.pf` execution history files, an NTFS Master File Table (MFT) parser for deep file system tracking, a registry structure inspector, and an automated artifact scanner designed to detect system indicators of compromise alongside a dedicated Windows Event Log review tool.

### Live System Imaging & Infrastructure
The application includes an initial implementation for creating live forensic ISO images tailored for offline analysis workflows, with graphical adaptations for WinPE environments currently under active development.

### Network, DLL Analysis, & System Maintenance
Network monitoring covers active TCP/UDP endpoint mapping to owner PIDs and process names, bolstered by built-in heuristic checks that flag anomalous or commonly abused ports offline without external API dependencies. A native PE header inspector allows deep analysis of imported APIs and export symbols. Finally, the system maintenance utilities include an interactive Windows Services manager, a startup application optimizer, an environment variables inspector, an installed software manager with uninstaller execution, and automated shortcuts for temporary file cleanup, recycle bin emptying, DNS cache flushing, Winsock/IP resets, and SFC/DISM integrity scans.

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
    <td align="center" width="50%" colspan="2">
      <img width="1919" height="1079" src="https://github.com/user-attachments/assets/5d5d6377-4488-4573-b51a-8c373813522e" alt="Artifact Scanner" /><br/>
      <sub><b>Artifact Scanner</b><br/><i>Automated System Artifacts & Indicators of Compromise</i></sub>
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
   git clone [https://github.com/Nooch98/ForensicTaskManager.git](https://github.com/Nooch98/ForensicTaskManager.git)
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
