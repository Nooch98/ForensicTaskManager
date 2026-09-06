# Forensic Task Manager (NexusGlassManager)

> **⚠️ Learning Project Disclaimer:** This project is built as a hands-on exercise to deepen my practical understanding of C++, the Win32 API, graphics rendering, and UI design patterns. Because I am actively learning, the codebase may contain bugs, inefficient algorithms, suboptimal patterns, or memory management flaws. Constructive feedback, code reviews, and issue reports are more than welcome!

## Technical Overview & Architecture

Forensic Task Manager is a custom Windows diagnostic utility that bridges low-level operating system APIs with an accelerated immediate-mode graphical user interface (GUI).

* **UI Framework:** [Dear ImGui](https://github.com/ocornut/imgui) (Docking branch enabled) utilizing a custom skinning layer to achieve a dynamic Glassmorphism aesthetic.
* **Graphics Backend:** OpenGL 3.0+ initialized directly through the Win32 window context (`wglCreateContext`).
* **System Interfacing:** Directly queries the Windows SDK (`TlHelp32.h`, `Psapi.h`, `Iphlpapi.h`, etc.) to extract process data, memory maps, threads, modules, and network connections.
* **Data Caching Pattern:** To mitigate UI stuttering caused by heavy blocking Win32 calls (such as `CreateToolhelp32Snapshot`), data is fetched and updated via a timed caching loop (`refreshTimer`) rather than every single frame.

## Core Features

* **Glassmorphic UI Engine:** Real-time adjustable transparency slider and external theme configuration loader (`LoadThemesFromFile`) with persistent local state saving.
* **Real-time Performance Graphs:** Custom historical ring-buffers tracking CPU, RAM, Disk, and Network activity.
* **Advanced Process Inspector:**
  * **Virtual Memory Map:** Enumerates memory regions, states, protections, and types (`VirtualQueryEx`).
  * **Modules & Threads:** Lists loaded DLLs, base addresses, thread IDs, and base priorities.
  * **Network Connections:** Tracks active TCP endpoints per process.
* **System Tools:** Windows services viewer, startup applications optimizer, environment variables inspector, and installed software manager with uninstaller execution.

## Gallery

<tr>
    <td align="center" width="50%">
      <img src="https://github.com/user-attachments/assets/1035db68-910b-49d0-b579-a6c65264afd4" alt="Process Inspector" /><br/>
      <sub><b>Advanced Process Inspector</b><br/><i>Virtual Memory, Modules, & TCP Endpoints</i></sub>
    </td>
    <td align="center" width="50%">
      <img src="https://github.com/user-attachments/assets/46f55bd0-3fee-4b79-af03-9932670f24ea" alt="DLL Viewer" /><br/>
      <sub><b>DLL Dependency Viewer</b><br/><i>Native PE Headers & Export Symbols</i></sub>
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
