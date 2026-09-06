<#
.SYNOPSIS
    Build script for Forensic Task Manager
#>

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Building Forensic Task Manager (Win32) " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Check if g++ is available in the system PATH
if (!(Get-Command g++ -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] 'g++' compiler not found in PATH. Please install MinGW-w64." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] Compiler detected successfully." -ForegroundColor Yellow
Write-Host "[INFO] Preparing source files and backend configurations..." -ForegroundColor Yellow

$sources = @(
    "taskmanager.cpp",
    "app.res",
    "imgui/imgui.cpp",
    "imgui/imgui_draw.cpp",
    "imgui/imgui_tables.cpp",
    "imgui/imgui_widgets.cpp",
    "imgui/imgui_impl_win32.cpp",
    "imgui/imgui_impl_opengl3.cpp"
)

$output = "ForensicTaskManager.exe"
$includes = "-Iimgui", "-I."

$libs = "-lopengl32", "-lgdi32", "-luser32", "-lshell32", "-lpsapi", "-lole32", "-loleaut32", "-luuid", "-liphlpapi", "-lws2_32", "-lcomdlg32", "-ldbghelp", "-ldwmapi"

Write-Host "[INFO] Compiling source code and linking Win32 / OpenGL libraries..." -ForegroundColor Yellow


& g++ @sources -o $output @includes @libs -mwindows -static-libgcc -static-libstdc++

if ($LASTEXITCODE -eq 0) {
    Write-Host "-----------------------------------------" -ForegroundColor Green
    Write-Host " [SUCCESS] Build completed successfully!   " -ForegroundColor Green
    Write-Host " [INFO] Executable generated: .\$output    " -ForegroundColor Cyan
    Write-Host "-----------------------------------------" -ForegroundColor Green
} else {
    Write-Host "-----------------------------------------" -ForegroundColor Red
    Write-Host " [ERROR] Compilation failed with errors. " -ForegroundColor Red
    Write-Host "-----------------------------------------" -ForegroundColor Red
    exit $LASTEXITCODE
}
